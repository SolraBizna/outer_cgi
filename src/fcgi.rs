#![allow(dead_code)]
use std;
use std::io;
use std::io::{Read, BufRead, Write};
use std::collections::HashMap;
use std::net::TcpStream;
use std::slice::Iter;
use super::{IO, Listener};
use options::{OptionHandler, OptionParseOutcome};
use std::panic::RefUnwindSafe;
use ctrlc;

// Types and constants from the FCGI specification, section 8

/*
 * Listening socket file number
 */
pub const LISTENSOCK_FILENO: i32 = 0;

// snip struct Header

/*
 * Number of bytes in a FCGI_Header.  Future versions of the protocol
 * will not reduce this number.
 */
pub const HEADER_LEN: usize = 8;

/*
 * Value for version component of FCGI_Header
 */
pub const VERSION_1: u8 = 1;

/*
 * Values for type component of FCGI_Header
 */
pub const BEGIN_REQUEST: u8 = 1;
pub const ABORT_REQUEST: u8 = 2;
pub const END_REQUEST: u8 = 3;
pub const PARAMS: u8 = 4;
pub const STDIN: u8 = 5;
pub const STDOUT: u8 = 6;
pub const STDERR: u8 = 7;
#[allow(dead_code)]
pub const DATA: u8 = 8;
pub const GET_VALUES: u8 = 9;
pub const GET_VALUES_RESULT: u8 = 10;
pub const UNKNOWN_TYPE: u8 = 11;
pub const MAXTYPE: u8 = UNKNOWN_TYPE;

/*
 * Value for requestId component of FCGI_Header
 */
pub const NULL_REQUEST_ID: u16 = 0;

// snip struct BeginRequestBody
// snip struct BeginRequestRecord

/*
 * Mask for flags component of FCGI_BeginRequestBody
 */
pub const KEEP_CONN: u8 = 1;

/*
 * Values for role component of FCGI_BeginRequestBody
 */
pub const RESPONDER: u16 = 1;
pub const AUTHORIZER: u16 = 2;
pub const FILTER: u16 = 3;

// snip struct EndRequestBody
// snip struct EndRequestRecord

/*
 * Values for protocolStatus component of FCGI_EndRequestBody
 */
pub const REQUEST_COMPLETE: u8 = 0;
pub const CANT_MPX_CONN: u8 = 1;
pub const OVERLOADED: u8 = 2;
pub const UNKNOWN_ROLE: u8 = 3;

/*
 * Variable names for FCGI_GET_VALUES / FCGI_GET_VALUES_RESULT records
 */
pub const MAX_CONNS: &str = "FCGI_MAX_CONNS";
pub const MAX_REQS: &str = "FCGI_MAX_REQS";
pub const MPXS_CONNS: &str = "FCGI_MPXS_CONNS";

// snip struct UnknownTypeBody
// snip struct UnknownTypeRecord

// and now, my implementation

// TODO: when `const fn` is stable, make this const and fix SENDBUF_SIZE
fn padding_for(i: usize) -> usize {
    if i & 7 != 0 { 8 - (i & 7) } else { 0 }
}

const MAX_CONTENT_LENGTH: usize = 65535;
const MAX_PADDING: usize = 255;
const LARGEST_POSSIBLE_RECORD_SIZE: usize
    = HEADER_LEN + MAX_CONTENT_LENGTH + MAX_PADDING;
const RECVBUF_SIZE: usize = LARGEST_POSSIBLE_RECORD_SIZE;
const SENDBUF_SIZE: usize = HEADER_LEN + MAX_CONTENT_LENGTH
    + 1;//padding_for(MAX_CONTENT_LENGTH);

#[repr(C,packed)]
#[derive(Debug,Copy,Clone)]
struct Header {
    version: u8,
    rectype: u8,
    request_id: u16,
    content_length: u16,
    padding_length: u8,
    reserved: u8,
}

type RecordType = u8;
type RequestId = u16;

fn read_length<T: io::Read>(reader: &mut T) -> Option<io::Result<u32>> {
    let mut b1: [u8; 1] = unsafe { std::mem::uninitialized() };
    match reader.read_exact(&mut b1[..]) {
        Ok(()) => (),
        Err(ref x) if x.kind() == io::ErrorKind::UnexpectedEof
            => return None,
        Err(x) => return Some(Err(x)),
    }
    if b1[0] & 0x80 != 0 {
        // it is a 31-bit length
        let mut b2: [u8; 3] = unsafe { std::mem::uninitialized() };
        match reader.read_exact(&mut b2[..]) {
            Ok(()) => (),
            Err(x) => return Some(Err(x)),
        }
        Some(Ok((((b1[0] & 0x80) as u32) << 24)
                | ((b2[0] as u32) << 16)
                | ((b2[1] as u32) << 8)
                | ((b2[2] as u32))))
    }
    else {
        // it is a 7-bit length
        Some(Ok(b1[0] as u32))
    }
}

fn write_length<T: io::Write>(writer: &mut T, length: usize) -> io::Result<()>{
    if length >= (1 << 31) {
        Err(io::Error::new(io::ErrorKind::Other,
                           "length too large to represent"))
    }
    else if length >= 128 {
        writer.write_all(&[(length >> 24) as u8 | 0x80,
                           (length >> 16) as u8,
                           (length >> 8) as u8,
                           length as u8])
    }
    else {
        writer.write_all(&[length as u8])
    }
}

struct KeyValueReader<R: io::Read> {
    reader: R,
}

impl<R: io::Read> KeyValueReader<R> {
    pub fn new(reader: R) -> Self { Self { reader } }
}

impl<R: io::Read> Iterator for KeyValueReader<R> {
    type Item = io::Result<(String, String)>;
    fn next(&mut self) -> Option<Self::Item> {
        let key_length = match read_length(&mut self.reader) {
            Some(Ok(x)) => x,
            Some(Err(x)) => return Some(Err(x)),
            None => return None,
        } as usize;
        let value_length = match read_length(&mut self.reader) {
            Some(Ok(x)) => x,
            Some(Err(x)) => return Some(Err(x)),
            None => return Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof))),
        } as usize;
        let mut key_buffer = Vec::new();
        let mut value_buffer = Vec::new();
        key_buffer.resize(key_length, 0);
        value_buffer.resize(value_length, 0);
        match self.reader.read_exact(key_buffer.as_mut_slice()) {
            Ok(()) => (),
            Err(x) => return Some(Err(x)),
        }
        match self.reader.read_exact(value_buffer.as_mut_slice()) {
            Ok(()) => (),
            Err(x) => return Some(Err(x)),
        }
        let key_string = match String::from_utf8(key_buffer) {
            Ok(x) => x,
            Err(x) => return Some(Err(io::Error::new(io::ErrorKind::Other,
                                                     x))),
        };
        let value_string = match String::from_utf8(value_buffer) {
            Ok(x) => x,
            Err(x) => return Some(Err(io::Error::new(io::ErrorKind::Other,
                                                     x))),
        };
        Some(Ok((key_string, value_string)))
    }
}

struct LowLevelReceiver {
    recvbufpos: u32,
    recvbufend: u32,
    recvbuf: [u8; RECVBUF_SIZE],
}

impl LowLevelReceiver {
    fn bytes_left_in_recvbuf(&self) -> u32 {
        self.recvbufend - self.recvbufpos
    }
    fn pivot_recvbuf(&mut self) {
        unsafe {
            std::ptr::copy((&self.recvbuf).as_ptr()
                           .offset(self.recvbufpos as isize),
                           (&mut self.recvbuf).as_mut_ptr(),
                           self.bytes_left_in_recvbuf() as usize);
        }
        self.recvbufend -= self.recvbufpos;
        self.recvbufpos = 0;
    }
    fn top_up_recvbuf<T>(&mut self, sock: &mut T) -> io::Result<()>
    where T: io::Read {
        if self.recvbufpos == self.recvbufend {
            // The buffer is empty, so it's helpful to move back to the
            // beginning
            self.recvbufpos = 0;
            self.recvbufend = 0;
        }
        else if self.recvbufend == RECVBUF_SIZE as u32 {
            // We have butted up against the end of the buffer.
            // This should never happen unless we are not positioned at the
            // beginning of the buffer.
            debug_assert!(self.recvbufpos > 0);
            self.pivot_recvbuf();
            debug_assert!(self.recvbufpos == 0);
        }
        let red = sock.read(&mut self.recvbuf[self.recvbufend as usize
                                              ..])?;
        if red == 0 {
            Err(io::Error::new(io::ErrorKind::Other,
                               "connection to webserver closed unexpectedly"))
        }
        else {
            self.recvbufend += red as u32;
            Ok(())
        }
    }
    fn get_record<'a, 'b, 'c, T>(&'a mut self, sock: &'b mut T)
                      -> io::Result<(RecordType, u16, &'c [u8])>
        where T: io::Read {
        while self.bytes_left_in_recvbuf() < HEADER_LEN as u32 {
            self.top_up_recvbuf(sock)?;
        }
        let header: &Header = unsafe {
            std::mem::transmute((&self.recvbuf).as_ptr()
                                .offset(self.recvbufpos as isize))
        };
        if header.version != VERSION_1 {
            return Err(io::Error::new(io::ErrorKind::Other,
                                      "received bad FCGI version"))
        }
        let rectype = header.rectype;
        if rectype == 0 || rectype > MAXTYPE {
            return Err(io::Error::new(io::ErrorKind::Other,
                                      "received bad FCGI record type"))
        }
        let request_id = u16::from_be(header.request_id);
        let content_length = u16::from_be(header.content_length) as u32;
        let padding_length = header.padding_length as u32;
        self.recvbufpos += HEADER_LEN as u32; // consume the header
        while self.bytes_left_in_recvbuf() < content_length + padding_length {
            self.top_up_recvbuf(sock)?;
        }
        let retslice = &self.recvbuf[self.recvbufpos as usize
                                     .. ((self.recvbufpos + content_length)
                                         as usize)];
        self.recvbufpos += content_length + padding_length;
        // screw the borrow checker!
        let real_retslice = unsafe {
            std::slice::from_raw_parts(retslice.as_ptr(), retslice.len())
        };
        Ok((rectype, request_id, real_retslice))
    }
}

pub struct Instance<'a, 'z> {
    sock: TcpStream,
    current_reqid: u16,
    current_input: RecordType,
    receiver: LowLevelReceiver,
    options: &'a Options,
    keep_conn: bool,
    input_has_ended: bool,
    remaining_slice_in_input: &'z[u8],
    sendbuf: [u8; SENDBUF_SIZE],
    stdout_pos: u32,
}

impl<'a, 'z> Instance<'a, 'z> {
    /// maxconns = number of concurrent connections we should claim to support
    pub fn new(sock: TcpStream, options: &'a Options) -> Instance<'a, 'z> {
        Instance {
            sock,
            current_reqid: NULL_REQUEST_ID,
            current_input: 0,
            receiver: LowLevelReceiver {
                recvbuf: unsafe { std::mem::uninitialized() },
                recvbufpos: 0,
                recvbufend: 0,
            },
            options,
            keep_conn: true,
            input_has_ended: true,
            remaining_slice_in_input: &[],
            sendbuf: unsafe { std::mem::uninitialized() },
            stdout_pos: 0,
        }
    }
    fn get_record<'b,'c>(&'b mut self) -> io::Result<(RecordType, &'c [u8])>{
        const APP_ONLY_TYPES: [RecordType; 4] = [
            GET_VALUES_RESULT, END_REQUEST, STDOUT, STDERR
        ];
        loop {
            let (rectype, request_id, content) =
                self.receiver.get_record(&mut self.sock)?;
            if rectype == 0 || rectype > MAXTYPE
            || APP_ONLY_TYPES.contains(&rectype) {
                self.respond(UNKNOWN_TYPE, 0,
                             &[rectype, 0, 0, 0, 0, 0, 0, 0])?;
                continue
            }
            else if rectype == GET_VALUES {
                if request_id != NULL_REQUEST_ID {
                    return Err(io::Error::new(io::ErrorKind::Other,
                                              "received bad FCGI record"))
                }
                let mut response_buffer = Vec::new();
                for res in KeyValueReader::new(content) {
                    let (k, v) = res?;
                    if !v.is_empty() {
                        return Err(io::Error::new(io::ErrorKind::Other,
                                                  "GET_VALUES contained \
                                                   values"))
                    }
                    let v = match k.as_str() {
                        MAX_CONNS | MAX_REQS =>
                            format!("{}", self.options.max_connections),
                        MPXS_CONNS => "1".to_owned(),
                        _ => continue,
                    };
                    write_length(&mut response_buffer, k.len())?;
                    write_length(&mut response_buffer, v.len())?;
                    response_buffer.write_all(k.as_bytes())?;
                    response_buffer.write_all(v.as_bytes())?;
                    if response_buffer.len() > MAX_CONTENT_LENGTH {
                        return Err(io::Error::new(io::ErrorKind::Other,
                                                  "GET_VALUES response \
                                                   would be too long"))
                    }
                }
                self.respond(GET_VALUES_RESULT, 0,
                             response_buffer.as_slice())?;
                continue
            }
            else {
                if rectype == BEGIN_REQUEST {
                    if request_id == NULL_REQUEST_ID {
                        return Err(io::Error::new(io::ErrorKind::Other,
                                                  "BEGIN_REQUEST with \
                                                   null request ID"))
                    }
                    else if self.current_reqid != NULL_REQUEST_ID {
                        self.respond(END_REQUEST, request_id,
                                     &[0,0,0,1,CANT_MPX_CONN,0,0,0])?;
                        continue
                    }
                    self.current_reqid = request_id;
                }
                else {
                    if request_id != self.current_reqid {
                        continue
                    }
                }
                return Ok((rectype, content))
            }
        }
    }
    fn begin_request(&mut self) -> io::Result<()> {
        self.current_input = PARAMS;
        self.input_has_ended = false;
        self.remaining_slice_in_input = &[];
        loop {
            self.current_reqid = NULL_REQUEST_ID;
            let (rectype, content) = self.get_record()?;
            if rectype != BEGIN_REQUEST {
                return Err(io::Error::new(io::ErrorKind::Other,
                                          "it was not a BEGIN_REQUEST record"))
            }
            if content.len() < 3 {
                return Err(io::Error::new(io::ErrorKind::Other,
                                          "BEGIN_REQUEST record was too \
                                           short"))
            }
            let flags = content[2];
            self.keep_conn = (flags & KEEP_CONN) != 0;
            let role = ((content[0] as u16) << 8) | (content[1] as u16);
            if role != RESPONDER {
                let reqid = self.current_reqid;
                self.respond(END_REQUEST, reqid,
                             &[0,0,0,1,UNKNOWN_ROLE,0,0,0])?;
                let error_string = format!("received a BEGIN_REQUEST with a \
                                            role other than RESPONDER (role \
                                            was {})",
                                           match role {
                                               AUTHORIZER =>
                                                   "AUTHORIZER".to_string(),
                                               FILTER => "FILTER".to_string(),
                                               x => x.to_string(),
                                           });
                return Err(io::Error::new(io::ErrorKind::Other,
                                          error_string))
            }
            break
        }
        Ok(())
    }
    fn read_environment(&mut self, env: &mut HashMap<String,String>)
                        -> io::Result<()> {
        self.current_input = PARAMS;
        self.input_has_ended = false;
        self.remaining_slice_in_input = &[];
        let kv_reader = KeyValueReader::new(self);
        for res in kv_reader {
            let (key, value) = res?;
            env.insert(key, value);
        }
        Ok(())
    }
    fn handle_request<H>(&mut self, handler: &H,
                         mut env: HashMap<String,String>) -> io::Result<()>
    where H: Fn(&mut dyn IO, HashMap<String, String>)
                -> io::Result<i32> {
        // get a BEGIN_REQUEST record
        self.begin_request()?;
        // read the parameters
        self.read_environment(&mut env)?;
        // become ready for stdin
        self.current_input = STDIN;
        self.input_has_ended = false;
        self.remaining_slice_in_input = &[];
        let result = handler(self, env);
        let status = match result {
            Ok(i) => unsafe { std::mem::transmute(i) },
            Err(_) => 127,
        } as u32;
        self.current_input = 0;
        let reqid = self.current_reqid;
        self.respond(END_REQUEST, reqid,
                     &[(status >> 24) as u8,
                       ((status >> 16) & 255) as u8,
                       ((status >> 8) & 255) as u8,
                       (status & 255) as u8,
                       REQUEST_COMPLETE,0,0,0])?;
        result.and(Ok(()))
    }
    pub fn handle_requests<H>(&mut self, handler: &H,
                              static_env: &HashMap<String,String>)
                              -> io::Result<()>
    where H: Fn(&mut dyn IO, HashMap<String, String>) -> io::Result<i32> {
        // keep_conn is initially true; it will be set to false when we receive
        // a BEGIN_REQUEST without KEEP_CONN. In the usual case, the first
        // BEGIN_REQUEST would lack KEEP_CONN, and therefore we would loop only
        // for one request.
        while self.keep_conn {
            self.handle_request(handler, static_env.clone())?;
        }
        Ok(())
    }
    fn respond(&mut self, rectype: RecordType, request_id: RequestId,
               content: &[u8]) -> io::Result<()> {
        assert!(content.len() <= MAX_CONTENT_LENGTH);
        self.flush()?; // in case of partial stdout
        let padding_length = padding_for(content.len());
        let buf = &mut self.sendbuf;
        buf[0] = VERSION_1;
        buf[1] = rectype;
        buf[2] = (request_id >> 8) as u8;
        buf[3] = (request_id & 255) as u8;
        buf[4] = ((content.len() >> 8) & 255) as u8;
        buf[5] = (content.len() & 255) as u8;
        buf[6] = padding_length as u8;
        buf[7] = 0;
        if content.len() == 0 {
            debug_assert!(padding_length == 0);
        }
        else {
            (&mut buf[HEADER_LEN..HEADER_LEN+content.len()])
                .copy_from_slice(content);
            if padding_length > 0 {
                for x in (&mut buf[HEADER_LEN+content.len()
                                   ..HEADER_LEN+content.len()+padding_length])
                    .iter_mut() {
                        *x = 0;
                    }
            }
        }
        self.sock.write_all(&buf[..HEADER_LEN+content.len()+padding_length])
    }
}

impl<'a, 'z> Read for Instance<'a, 'z> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.fill_buf()?.read(buf) {
            Ok(x) => { self.consume(x); Ok(x) },
            Err(e) => { Err(e) },
        }
    }
}

impl<'a, 'z> BufRead for Instance<'a, 'z> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.input_has_ended { return Ok(&[]) }
        if self.remaining_slice_in_input.is_empty() {
            let (rectype, content) = self.get_record()?;
            if rectype != self.current_input {
                return Err(io::Error::new(io::ErrorKind::Other,
                                          "we were expecting a stream \
                                           record but we got another kind \
                                           instead"))
            }
            if content.len() == 0 { self.input_has_ended = true }
            self.remaining_slice_in_input = content;
        }
        Ok(self.remaining_slice_in_input)
    }
    fn consume(&mut self, amount: usize) {
        self.remaining_slice_in_input
            = &self.remaining_slice_in_input[amount..];
    }
}

impl<'a, 'z> Write for Instance<'a, 'z> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let stdout_pos = self.stdout_pos as usize;
        let amount = (MAX_CONTENT_LENGTH - stdout_pos).min(buf.len());
        (&mut self.sendbuf[HEADER_LEN+stdout_pos
                           ..HEADER_LEN+stdout_pos+amount])
            .copy_from_slice(&buf[..amount]);
        self.stdout_pos += amount as u32;
        if self.stdout_pos == MAX_CONTENT_LENGTH as u32 {
            self.flush()?;
        }
        Ok(amount)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.stdout_pos != 0 {
            let stdout_pos = self.stdout_pos as usize;
            let padding_length = padding_for(stdout_pos);
            let buf = &mut self.sendbuf;
            buf[0] = VERSION_1;
            buf[1] = STDOUT;
            buf[2] = (self.current_reqid >> 8) as u8;
            buf[3] = (self.current_reqid & 255) as u8;
            buf[4] = ((stdout_pos >> 8) & 255) as u8;
            buf[5] = (stdout_pos & 255) as u8;
            buf[6] = padding_length as u8;
            buf[7] = 0;
            if padding_length > 0 {
                for x in (&mut buf[HEADER_LEN+stdout_pos
                                   ..HEADER_LEN+stdout_pos+padding_length])
                    .iter_mut() {
                        *x = 0;
                    }
            }
            self.sock.write_all(&buf[..HEADER_LEN+stdout_pos+padding_length])?;
            self.stdout_pos = 0;
        }
        Ok(())
    }
}

impl<'a, 'z> IO for Instance<'a, 'z> {}

pub struct Options {
    pub max_connections: u32,
}
impl Options {
    pub fn new() -> Options { Options { max_connections: 10 } }
}
impl OptionHandler for Options {
    fn maybe_parse_option<'a>(&mut self, arg: &str, it: &mut Iter<String>)
                              -> OptionParseOutcome {
        match arg {
            "--max-connections" => {
                let max_connections = match it.next() {
                    Some(max_connections) => max_connections,
                    None => {
                        eprintln!("Missing argument for --max-connections");
                        return OptionParseOutcome::Failed
                    },
                };
                match max_connections.parse() {
                    Err(_) => {
                        eprintln!("Invalid argument for --max-connections");
                        return OptionParseOutcome::Failed
                    },
                    Ok(max_connections)
                    if max_connections < 1 || max_connections > 10000 => {
                        eprintln!("Invalid argument for --max-connections");
                        return OptionParseOutcome::Failed
                    },
                    Ok(max_connections) => {
                        self.max_connections = max_connections;
                        OptionParseOutcome::Consumed
                    }
                }
            },
            _ => OptionParseOutcome::Ignored,
        }
    }
}

// listener must be in a box so it can be sent to the listen thread. We could
// use a reference and lie about its lifetime, but we've already lied to the
// borrow checker more than is good.
pub fn listen_loop<H>(mut listener: Box<dyn Listener>, handler: H,
                      options: Options,
                      static_env: &HashMap<String,String>)
                      -> i32
where H: 'static + Fn(&mut dyn IO, HashMap<String, String>) -> io::Result<i32>
    + Sync + Send + Copy + RefUnwindSafe {
    use crossbeam_channel as cc;
    // Lie to the borrow checker. The difficult-to-encode assumption is that
    // all child references will have been joined before this function returns.
    let static_env: &'static HashMap<String,String> =
        unsafe{std::mem::transmute(static_env)};
    // The first control-C tries to gracefully terminate the server after
    // handling all outstanding requests. The second one kills the server.
    // Subsequent ones don't matter. (We must use bounded for this because it
    // would be suicide to allocate from a signal handler, especially if it's
    // Windows's trivial replacement.)
    let (ctrlc_tx, ctrlc_rx) = cc::bounded(1);
    ctrlc::set_handler(move || {
        match ctrlc_tx.try_send(()) {
            Ok(_) => {
                // I'm pretty sure this is safe to do from a signal handler.
                // Pretty sure...
                eprintln!("Shutdown requested. Waiting for existing requests \
                           to finish.");
            },
            Err(_) => std::process::exit(1),
        }
    }).expect("Error setting graceful termination handler");
    // We want the listen thread to block until the manager is ready to
    // dispatch a connection before accepting another. This way, at most one
    // incoming connection can fail *after* accept(), if graceful termination
    // is requested.
    let (listen_tx, listen_rx) = cc::bounded(0);
    std::thread::Builder::new()
        .name("listener".to_string())
        .spawn(move || {
        // Repeatedly listen for connections, until we get an error.
        loop {
            let to_send = listener.accept_connection();
            let should_break = to_send.is_err();
            // If sending failed, we're on our way down too...
            if !listen_tx.send(to_send).is_ok() { break }
            if should_break { break }
        }
    }).expect("Error spawning listen thread");
    // We only want a send on worker_tx to succeed when a worker thread is
    // actually ready to deal with the new connection, so we pass a backlog of
    // 0. This means that if a graceful termination is requested while all
    // workers are currently busy, at least one more request may end up being
    // handled. That's okay.
    let (worker_tx, worker_rx) = cc::bounded(0);
    let mut threads = Vec::with_capacity(options.max_connections as usize);
    for n in 0 .. options.max_connections {
        let worker_rx = worker_rx.clone();
        let options: &'static Options =
            unsafe{std::mem::transmute(&options)};
        threads.push(std::thread::Builder::new()
                     .name(format!("worker {}", (n as usize)+1))
                     .spawn(move || {
            // Do NOT catch a panic in worker_rx.recv(), because there's no way
            // that ends well.
            while let Ok(sock) = worker_rx.recv() {
                let result = std::panic::catch_unwind(|| {
                    let mut instance = Instance::new(sock, options);
                    match instance.handle_requests(&handler, static_env) {
                        Ok(_) => (),
                        Err(e) => eprintln!("error handling request: {}",e),
                    }});
                match result {
                    Ok(_) => (),
                    Err(_) => {
                        // The panic hook already outputted info for this panic
                        eprintln!("SERIOUS: Panicked while handling request!");
                    },
                }
            }
            // If we got here, our receiver closed. That means graceful
            // shutdown is in progress. Exit.
        }).expect("Error spawning worker thread"));
    }
    let exit_code;
    loop {
        let result = select_loop! {
            recv(ctrlc_rx, _) => {
                Some(0)
            },
            recv(listen_rx, result) => {
                match result {
                    Err(e) => {
                        eprintln!("Error on listen socket: {}", e);
                        // Gracefully shut down after all outstanding
                        // connections are closed
                        Some(1)
                    },
                    Ok(sock) => {
                        worker_tx.send(sock).expect("Error dispatching \
                                                     incoming connection");
                        None
                    },
                }
            },
            disconnected() => {
                eprintln!("Internal error: Control-C and listen threads both \
                           died!");
                Some(1)
            },
        };
        match result {
            None => continue,
            Some(code) => {
                exit_code = code;
                break
            }
        }
    }
    // Close the channels. The respective threads will terminate gracefully,
    // though the listen thread will probably not get the chance unless the
    // server is busy.
    std::mem::drop(ctrlc_rx);
    std::mem::drop(listen_rx);
    std::mem::drop(worker_tx);
    for thread in threads {
        thread.join().expect("Error joining worker thread")
    }
    exit_code
}
