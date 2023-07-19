//! This crate is a thin CGI/FCGI wrapper. It turns your program into an
//! adaptive CGI script; capable of being invoked as CGI or FCGI in a variety
//! of configurations.
//!
//! This is *not* a full web framework. It performs minimal validation, and no
//! parsing beyond the bare minimum required to pass one or more CGI-style
//! requests to your handler. Examples of things that `outer_cgi` **does not
//! do**:
//!
//! - Validate environment variables, beyond checking that `GATEWAY_INTERFACE`
//! begins with `"CGI/"`, when invoked as a CGI.
//! - Parse query strings or cookies.
//! - Provide a template engine.
//! - Provide any database interfaces.
//!
//! Here is what it **does** do:
//!
//! - Seamlessly supports operation as either CGI or FCGI.
//! - FCGI may either be spawned in the "standard" way (where stdin is a listen
//! socket) or by explicitly binding to either a TCP port or UNIX socket.
//! - The UNIX version supports the following additional features:
//!     - `setuid`, `setgid`, and `chroot` for privilege reduction.
//!     - Logging to `syslog`, either out of necessity (from being spawned as
//! FCGI by another process) or by user request.
//!     - Daemonization.
//!
//! You write your code as a simple CGI script, using `outer_cgi`'s
//! replacements for `stdin`, `stdout`, and `env`. `outer_cgi` then allows the
//! webmaster to deploy your script in whatever configuration is most suitable.
//!
//! ```rust,no_run
//! extern crate outer_cgi;
//! use std::collections::HashMap;
//! use outer_cgi::IO;
//!
//! fn handler(io: &mut IO, env: HashMap<String, String>) -> anyhow::Result<i32> {
//!     io.write_all(format!(r#"Content-type: text/plain; charset=utf-8
//!
//! Hello World! Your request method was "{}"!
//! "#, env.get("REQUEST_METHOD").unwrap()).as_bytes())?;
//!     Ok(0)
//! }
//!
//! pub fn main() {
//!     outer_cgi::main(|_|{}, handler)
//! }
//! ```
//!
//! See the [Common Gateway Interface][1] specification for more information.
//!
//! According to the RFC, the current working directory SHOULD be the directory
//! containing the script. It's up to the webmaster to ensure this is the case
//! when running as an FCGI.
//!
//! [1]: https://tools.ietf.org/html/rfc3875

use std::{
    collections::HashMap,
    io,
    io::{Read, BufRead, Write, BufWriter},
    net::{SocketAddr, IpAddr, TcpStream, TcpListener},
    panic::RefUnwindSafe,
    path::PathBuf,
};

#[cfg(unix)] mod unix;

mod fcgi;
mod options;

use options::*;

/// Used internally to allow Rust TcpListener to coexist with a UNIX domain
/// socket. We also wrap the `FCGI_WEB_SERVER_ADDRS` checking in one of these.
#[doc(hidden)]
pub trait Listener : Send {
    /// Blocks until a new connection arrives. Returns a stream for the new
    /// connection. (This may not actually be a `TcpStream` on UNIX, but a UNIX
    /// domain socket in `TcpStream`'s clothing! Some day I should replace this
    /// with a trait like `IO` instead... but then it ends up in a box on the
    /// heap... sigh.)
    fn accept_connection(&mut self) -> io::Result<TcpStream>;
}

impl Listener for TcpListener {
    fn accept_connection(&mut self) -> io::Result<TcpStream> {
        self.accept().map(|(x, _)| x)
    }
}

struct ParanoidTcpListener {
    listener: TcpListener,
    whitelist: Vec<IpAddr>,
}
impl ParanoidTcpListener {
    fn make_whitelist(whitelist: &str) -> io::Result<Vec<IpAddr>> {
        let mut ret = Vec::new();
        for result in whitelist.as_bytes().split(|x| *x == b',')
        .map(|mut x| {
            while !x.is_empty() && x[0] == b' ' {
                x = &x[1..];
            }
            while !x.is_empty() && x[x.len()-1] == b' ' {
                x = &x[..x.len()-1];
            }
            unsafe{String::from_utf8_unchecked(x.to_vec())}.parse()
        }) {
            match result {
                Ok(addr) => ret.push(addr),
                Err(_) => return Err(io::Error::new(io::ErrorKind::Other,
                                                    "Invalid address in \
                                                     FCGI_WEB_SERVER_ADDRS")),
            }
        }
        Ok(ret)
    }
    fn new(addr: SocketAddr, whitelist: &str)
           -> io::Result<ParanoidTcpListener> {
        let whitelist = ParanoidTcpListener::make_whitelist(whitelist)?;
        Ok(ParanoidTcpListener {
            listener: TcpListener::bind(addr)?,
            whitelist,
        })
    }
    #[allow(unused)]
    fn with(listener: TcpListener, whitelist: &str)
           -> io::Result<ParanoidTcpListener> {
        let whitelist = ParanoidTcpListener::make_whitelist(whitelist)?;
        Ok(ParanoidTcpListener {
            listener,
            whitelist,
        })
    }
}

impl Listener for ParanoidTcpListener {
    fn accept_connection(&mut self) -> io::Result<TcpStream> {
        loop {
            let (sock, addr) = self.listener.accept()?;
            let ip = addr.ip();
            for white in self.whitelist.iter() {
                if ip == *white { return Ok(sock) }
            }
        }
    }
}

/// Wraps the stdin and stdout streams of a standard CGI invocation.
///
/// See the [Common Gateway Interface][1] specification for more information.
///
/// [1]: https://tools.ietf.org/html/rfc3875
pub trait IO : BufRead + Write {
}

struct DualIO<R: BufRead, W: Write> {
    i: R,
    o: W,
}

impl<R: BufRead, W: Write> Read for DualIO<R, W> {
    fn read(&mut self, buf: &mut[u8]) -> io::Result<usize> {
        self.i.read(buf)
    }
}

impl<R: BufRead, W: Write> BufRead for DualIO<R, W> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.i.fill_buf()
    }
    fn consume(&mut self, amount: usize) {
        self.i.consume(amount)
    }
}

impl<R: BufRead, W: Write> Write for DualIO<R, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.o.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.o.flush()
    }
}

impl<R: BufRead, W: Write> IO for DualIO<R, W> {
}

/// The first (and preferably only) function your program's `main` function
/// should call. Handles argument parsing, worker thread spawning, etc. For
/// each request, calls the handler you provide.
///
/// `init` is called once, before any requests are handled. It is passed the
/// maximum number of parallel connections that will be handled by this
/// instance. You should perform initialization (read templates, set up
/// database connection pools, etc.) in this function. If you don't need any
/// such setup, just pass `|_|{}`.
///
/// Your handler receives the standard set of CGI streams and environment
/// variables as parameters. It should use them instead of the usual Rust
/// `stdin`/`stdout`/`env` facilities. `outer_cgi` tries to ensure that the
/// usual `stderr` facility (`eprintln!` etc.) is usable for logging error
/// information.
///
/// `outer_cgi::main` does not return. It handles as many requests as possible,
/// then calls `std::process::exit` as appropriate. You shouldn't call anything
/// but `outer_cgi::main` from your script's `main` function;
/// `stdin`/`stdout`/`stderr` may be in an incoherent state, and if you spawn
/// any threads before calling `outer_cgi::main`, they may silently die in some
/// configurations. Perform any per-process setup on-demand, the first time
/// your `handler` is called, instead.
///
/// See the [Common Gateway Interface][1] specification and the module-level
/// documentation for more information.
///
/// [1]: https://tools.ietf.org/html/rfc3875
pub fn main<I, H>(init: I, handler: H) -> !
where I: 'static + Fn(u32),
      H: 'static + Fn(&mut dyn IO, HashMap<String, String>) -> anyhow::Result<i32>
    + Sync + Send + Copy + RefUnwindSafe {
    use std::process::exit;
    match sub_main(init, handler) {
        Ok(i) => exit(i),
        Err(e) => {
            eprintln!("Unexpected error: {}", e);
            exit(1)
        }
    }
}

fn sub_main<I, H>(init: I, handler: H) -> anyhow::Result<i32>
where I: 'static + Fn(u32),
      H: 'static + Fn(&mut dyn IO, HashMap<String, String>) -> anyhow::Result<i32>
    + Sync + Send + Copy + RefUnwindSafe {
    let args: Vec<String> = std::env::args().collect();
    let static_env: HashMap<String, String> = std::env::vars().collect();
    if args.len() <= 1 {
        if let Some(existing_listener) = fix_fds(&static_env) {
            // FCGI server spawned by someone else. We'll handle one request
            // at a time.
            init(1);
            Ok(fcgi::listen_loop(existing_listener,
                                 handler,
                                 fcgi::Options { max_connections:1 },
                                 &static_env))
        }
        else if let Some(_) = static_env.get("GATEWAY_INTERFACE") {
            init(1);
            // A bit convoluted to satisfy the borrow checker.
            if !static_env.get("GATEWAY_INTERFACE").unwrap()
            .starts_with("CGI/") {
                // Some unknown foreign gateway interface
                eprintln!("Unknown GATEWAY_INTERFACE type");
                return Ok(1)
            }
            // CGI process spawned by web server. Simplest case.
            let stdin = io::stdin();
            let stdout = io::stdout();
            let mut io = DualIO {
                i: stdin.lock(),
                o: BufWriter::new(stdout.lock()),
            };
            handler(&mut io, static_env)
        }
        else {
            print_usage();
            Ok(1)
        }
    }
    else {
        match args[1].as_str() {
            "fcgi-tcp" => {
                let mut bind_options: BindOptions<SocketAddr>
                    = BindOptions::new();
                let mut fcgi_options = fcgi::Options::new();
                let mut os_options = os_options();
                if !handle_command_line(&mut [
                    &mut bind_options,
                    &mut fcgi_options,
                    &mut os_options,
                ], args[2..].iter()) {
                    print_usage();
                    Ok(1)
                }
                else if bind_options.addr.is_none() {
                    eprintln!("Please specify an address and port to bind to \
                               using --bind");
                    print_usage();
                    Ok(1)
                }
                else {
                    let listener: Box<dyn Listener> =
                    if let Some(list)=static_env.get("FCGI_WEB_SERVER_ADDRS") {
                        Box::new(ParanoidTcpListener::new(bind_options.addr
                                                          .unwrap(), list)?)
                    }
                    else {
                        Box::new(TcpListener::bind(bind_options.addr
                                                   .unwrap())?)
                    };
                    os_options.post_setup()?;
                    init(fcgi_options.max_connections);
                    Ok(fcgi::listen_loop(listener, handler, fcgi_options,
                                         &static_env))
                }
            },
            #[cfg(unix)] "fcgi-unix" => {
                let mut bind_options: BindOptions<PathBuf>
                    = BindOptions::new();
                let mut unix_socket_options = unix::UnixSocketOptions::new();
                let mut fcgi_options = fcgi::Options::new();
                let mut os_options = os_options();
                if !handle_command_line(&mut [
                    &mut bind_options,
                    &mut unix_socket_options,
                    &mut fcgi_options,
                    &mut os_options,
                ], args[2..].iter()) {
                    print_usage();
                    Ok(1)
                }
                else if bind_options.addr.is_none() {
                    eprintln!("Please specify a filesystem path to bind to \
                               using --bind");
                    print_usage();
                    Ok(1)
                }
                else {
                    if let Some(_) = static_env.get("FCGI_WEB_SERVER_ADDRS") {
                        eprintln!("WARNING: Value of FCGI_WEB_SERVER_ADDRS is \
                                   ignored for non-TCP sockets!");
                    }
                    let listener
                        = unix::listen(bind_options.addr.unwrap().as_path(),
                                       unix_socket_options)?;
                    os_options.post_setup()?;
                    init(fcgi_options.max_connections);
                    Ok(fcgi::listen_loop(Box::new(listener), handler,
                                         fcgi_options, &static_env))
                }
            },
            x => {
                eprintln!("Unknown mode: {}", x);
                print_usage();
                Ok(1)
            },
        }
    }
}

