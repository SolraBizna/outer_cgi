use std::{
    collections::HashMap,
    ffi::CString,
    fs::File,
    io,
    io::{BufRead, BufReader},
    net::{TcpStream, TcpListener},
    os::unix::{
        io::{RawFd,FromRawFd,IntoRawFd,AsRawFd},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    slice::Iter,
};

use libc::mode_t;
use nix::{
    fcntl::FcntlArg,
    sys::stat::SFlag,
    sys::socket::SockaddrIn,
};

use super::{Listener, ParanoidTcpListener, OptionHandler, OptionParseOutcome};

fn fd_ok(fd: RawFd) -> bool {
    match nix::fcntl::fcntl(fd, FcntlArg::F_GETFD) {
        // The file descriptor is open and valid.
        Ok(_) => true,
        // The file descriptor is not open.
        Err(nix::Error::EBADF) => false,
        // The fcntl call failed for some other reason. Panic, for all the good
        // that'll do.
        Err(e) => panic!("error calling fcntl({}): {}", fd, e),
    }
}

fn fd_is_sock(fd: RawFd) -> bool {
    let st = nix::sys::stat::fstat(fd)
        .expect("Unexpected error calling fstat");
    (SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT) == SFlag::S_IFSOCK 
}

fn stderr_to_syslog(identifier: Option<String>) {
    // let's make a pipe
    let (read_fd, write_fd) = nix::unistd::pipe()
        .expect("Unexpected error making syslog diversion pipe");
    assert_ne!(read_fd, 2);
    if write_fd != 2 {
        nix::unistd::dup2(write_fd, 2)
            .expect("Unexpected error calling dup2 on syslog diversion pipe");
        let _ = nix::unistd::close(write_fd); // ignore error
    }
    let read = unsafe { File::from_raw_fd(read_fd) };
    // identifier needs to hang around as long as we keep calling syslog, or
    // bad things will happen! therefore, we will move it into the closure
    let identifier = identifier.unwrap_or_else(|| {
        std::env::args().next()
            .map(|x| {
                match x.rfind('/') {
                    Some(i) => x[i+1..].to_owned(),
                    None => x,
                }
            }).unwrap_or_else(|| "outer_cgi_app".to_string())
    });
    let identifier = CString::new(identifier).unwrap();
    use nix::unistd::ForkResult;
    match unsafe{nix::unistd::fork()} {
        Ok(ForkResult::Child) => {
            let _ = nix::unistd::close(write_fd); // ignore result
            unsafe {
                libc::openlog(identifier.as_ptr(), 0, libc::LOG_USER);
            }
            let mut read = BufReader::new(read);
            let mut buf = Vec::new();
            while let Ok(count) = read.read_until(b'\n', &mut buf) {
                if count == 0 { break }
                buf.push(0);
                unsafe {
                    libc::syslog(libc::LOG_WARNING,
                                 b"%s\0".as_ptr() as *const libc::c_char,
                                 buf.as_ptr() as *const libc::c_char);
                }
                buf.clear();
            }
            std::process::exit(0)
        },
        Ok(ForkResult::Parent{..}) => {
            let _ = nix::unistd::close(read_fd); // ignore result
        },
        Err(_) => {
            // panic, for all the good it'll do
            panic!("forking for syslog diversion failed!");
        }
    }
}

/// If we are being run in strict compliance with the FCGI specification
/// file descriptor 0 (normally stdin) is an FCGI listen socket, and file
/// descriptors 1 and 2 (stdout/stderr) are closed. In addition, even if those
/// FDs are valid, if FD 0 is a socket then stderr might not go to a place that
/// makes any sense.
///
/// This function:
/// - Ensures that FDs 0, 1, and 2 are valid, to avoid problems down the line.
/// - Detects whether FD 0 is a listen socket, and returns a Listener for it if
/// so.
/// - If FD 2 was invalid **IOR** FD 0 was a listen socket, redirects stderr
/// to syslog, with an automatically generated identifier.
pub fn fix_fds(env: &HashMap<String,String>) -> Option<Box<dyn Listener>> {
    // let's ensure that all standard file descriptors are valid
    let fd0_ok = fd_ok(0);
    let fd1_ok = fd_ok(1);
    let fd2_ok = fd_ok(2);
    if !fd0_ok || !fd1_ok || !fd2_ok {
        // at least one of the standard FDs is not open.
        let devnull = nix::fcntl::open("/dev/null", nix::fcntl::OFlag::O_RDWR,
                                       nix::sys::stat::Mode::empty())
            .expect("Error opening /dev/null");
        if !fd0_ok && devnull != 0 { nix::unistd::dup2(devnull, 0).unwrap(); }
        if !fd1_ok && devnull != 1 { nix::unistd::dup2(devnull, 1).unwrap(); }
        // (yes, we're just going to close fd 2 in a moment anyway, but this
        // way we ensure pipe() doesn't return file descriptor 2 as the read
        // end of the stderr pipe)
        if !fd2_ok && devnull != 2 { nix::unistd::dup2(devnull, 2).unwrap(); }
        if devnull > 2 { nix::unistd::close(devnull).unwrap(); }
    }
    // if FD 2 doesn't go anywhere OR FD 0 is a listen socket
    let have_sock = fd_is_sock(0);
    if !fd2_ok || have_sock {
        stderr_to_syslog(None)
    }
    if fd0_ok && have_sock {
        if let Some(list) = env.get("FCGI_WEB_SERVER_ADDRS") {
            let result: Result<SockaddrIn, _> = nix::sys::socket::getsockname(0);
            match result {
                Ok(_) => {
                    Some(Box::new(unsafe{
                        ParanoidTcpListener::with(TcpListener::from_raw_fd(0),
                                                  list).unwrap()
                    }))
                },
                _ => {
                    eprintln!("WARNING: Value of FCGI_WEB_SERVER_ADDRS is \
                               ignored for non-TCP sockets!");
                    Some(Box::new(unsafe{TcpListener::from_raw_fd(0)}))
                },
            }
        }
        else {
            // A bare listener will do
            Some(Box::new(unsafe{TcpListener::from_raw_fd(0)}))
        }
    }
    else {
        None
    }
}

pub struct UnixSocketOptions {
    chown: Option<nix::unistd::Uid>,
    chgrp: Option<nix::unistd::Gid>,
    chmod: Option<nix::sys::stat::Mode>,
}
impl UnixSocketOptions {
    pub fn new() -> UnixSocketOptions {
        UnixSocketOptions {
            chown: None,
            chgrp: None,
            chmod: None,
        }
    }
}
impl OptionHandler for UnixSocketOptions {
    fn maybe_parse_option<'a>(&mut self, arg: &str, it: &mut Iter<String>)
                              -> OptionParseOutcome {
        match arg {
            "--chmod" => {
                let arg = match it.next() {
                    Some(arg) => arg,
                    None => {
                        eprintln!("Missing argument for --chmod");
                        return OptionParseOutcome::Failed
                    },
                };
                match mode_t::from_str_radix(arg, 8) {
                    Err(_) => {
                        eprintln!("Invalid argument for --chmod");
                        return OptionParseOutcome::Failed
                    },
                    Ok(mode) if mode > 0o777 => {
                        eprintln!("Invalid argument for --chmod");
                        return OptionParseOutcome::Failed
                    },
                    Ok(mode) => {
                        self.chmod = Some(nix::sys::stat::Mode::from_bits_truncate(mode));
                        OptionParseOutcome::Consumed
                    }
                }
            },
            "--chown" => {
                let arg = match it.next() {
                    Some(arg) => arg,
                    None => {
                        eprintln!("Missing argument for --chown");
                        return OptionParseOutcome::Failed
                    },
                };
                match libc::uid_t::from_str_radix(arg, 10) {
                    Err(_) => {
                        eprintln!("Invalid argument for --chown");
                        return OptionParseOutcome::Failed
                    },
                    Ok(mode) => {
                        self.chown = Some(nix::unistd::Uid::from_raw(mode));
                        OptionParseOutcome::Consumed
                    }
                }
            },
            "--chgrp" => {
                let arg = match it.next() {
                    Some(arg) => arg,
                    None => {
                        eprintln!("Missing argument for --chgrp");
                        return OptionParseOutcome::Failed
                    },
                };
                match libc::gid_t::from_str_radix(arg, 10) {
                    Err(_) => {
                        eprintln!("Invalid argument for --chgrp");
                        return OptionParseOutcome::Failed
                    },
                    Ok(mode) => {
                        self.chgrp = Some(nix::unistd::Gid::from_raw(mode));
                        OptionParseOutcome::Consumed
                    }
                }
            },
            _ => OptionParseOutcome::Ignored,
        }
    }
}

impl Listener for UnixListener {
    fn accept_connection(&mut self) -> io::Result<TcpStream> {
        match self.accept() {
            Ok((sock, _)) => Ok(unsafe{TcpStream::from_raw_fd(sock.into_raw_fd())}),
            Err(e) => Err(e),
        }
    }
}

pub fn listen(path: &Path, options: UnixSocketOptions)
              -> io::Result<UnixListener> {
    // This will cause the socket to be created with the desired permissions.
    let old_umask = unsafe{libc::umask(options.chmod.map(|x| x.bits()).unwrap_or(0o660)^0o777)};
    let ret = UnixListener::bind(path)?;
    // restore the old umask
    unsafe{libc::umask(old_umask)};
    if options.chown.is_some() || options.chgrp.is_some() {
        match nix::unistd::chown(path, options.chown, options.chgrp) {
            Ok(_) => (),
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        }
        // now, consume any connections that might have been made while the
        // owner/group were wrong
        // (this should not error; I think panicking on a near-impossible
        // situation that would break code downstream is better than
        // either copy-pasting the same error conversion shim twice more or
        // just ignoring the result)
        nix::fcntl::fcntl(ret.as_raw_fd(),
                          FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK))
            .unwrap();
        while let Ok(_) = ret.accept() {}
        nix::fcntl::fcntl(ret.as_raw_fd(),
                          FcntlArg::F_SETFL(nix::fcntl::OFlag::empty()))
            .unwrap();
    }
    Ok(ret)
}

pub struct UnixOSOptions {
    setuid: Option<nix::unistd::Uid>,
    setgid: Option<nix::unistd::Gid>,
    chroot: Option<PathBuf>,
    syslog: Option<String>,
    daemonize: bool,
}
impl UnixOSOptions {
    pub fn new() -> UnixOSOptions {
        UnixOSOptions {
            setuid: None,
            setgid: None,
            chroot: None,
            syslog: None,
            daemonize: false,
        }
    }
    fn nix_post_setup(self) -> nix::Result<()> {
        if let Some(path) = &self.chroot {
            nix::unistd::chroot(path)?;
        }
        if let Some(gid) = self.setgid {
            nix::unistd::setgid(gid)?;
        }
        if let Some(uid) = self.setuid {
            nix::unistd::setuid(uid)?;
        }
        if let Some(identifier) = self.syslog {
            stderr_to_syslog(Some(identifier));
        }
        if self.daemonize {
            // use the old double-fork trick
            // use libc::_exit instead of std::process::exit because we don't
            // *want* to clean anything up
            use nix::unistd::ForkResult;
            match unsafe{nix::unistd::fork()}? {
                ForkResult::Child =>
                    match unsafe{nix::unistd::fork()}? {
                        ForkResult::Child => (),
                        _ => unsafe { libc::_exit(0) },
                    },
                _ => unsafe { libc::_exit(0) },
            }
            let devnull = nix::fcntl::open("/dev/null",
                                           nix::fcntl::OFlag::O_RDWR,
                                           nix::sys::stat::Mode::empty())
                .unwrap();
            if devnull != 0 { nix::unistd::dup2(devnull, 0).unwrap(); }
            if devnull != 1 { nix::unistd::dup2(devnull, 1).unwrap(); }
            if devnull >= 2 { nix::unistd::close(devnull).unwrap(); }
        }
        Ok(())
    }
    pub fn post_setup(self) -> io::Result<()> {
        self.nix_post_setup().map_err(|x|
                                      io::Error::new(io::ErrorKind::Other,x))
    }
}
impl OptionHandler for UnixOSOptions {
    fn maybe_parse_option<'a>(&mut self, arg: &str, it: &mut Iter<String>)
                              -> OptionParseOutcome {
        match arg {
            "--setuid" => {
                let arg = match it.next() {
                    Some(arg) => arg,
                    None => {
                        eprintln!("Missing argument for --setuid");
                        return OptionParseOutcome::Failed
                    },
                };
                match libc::uid_t::from_str_radix(arg, 10) {
                    Err(_) => {
                        eprintln!("Invalid argument for --setuid");
                        return OptionParseOutcome::Failed
                    },
                    Ok(mode) => {
                        self.setuid = Some(nix::unistd::Uid::from_raw(mode));
                        OptionParseOutcome::Consumed
                    }
                }
            },
            "--setgid" => {
                let arg = match it.next() {
                    Some(arg) => arg,
                    None => {
                        eprintln!("Missing argument for --setgid");
                        return OptionParseOutcome::Failed
                    },
                };
                match libc::gid_t::from_str_radix(arg, 10) {
                    Err(_) => {
                        eprintln!("Invalid argument for --setgid");
                        return OptionParseOutcome::Failed
                    },
                    Ok(mode) => {
                        self.setgid = Some(nix::unistd::Gid::from_raw(mode));
                        OptionParseOutcome::Consumed
                    }
                }
            },
            "--chroot" => {
                let arg = match it.next() {
                    Some(arg) => arg,
                    None => {
                        eprintln!("Missing argument for --chroot");
                        return OptionParseOutcome::Failed
                    },
                };
                self.chroot = Some(PathBuf::from(arg));
                OptionParseOutcome::Consumed
            },
            "--syslog" => {
                let arg = match it.next() {
                    Some(arg) => arg,
                    None => {
                        eprintln!("Missing argument for --syslog");
                        return OptionParseOutcome::Failed
                    },
                };
                self.syslog = Some(arg.to_owned());
                OptionParseOutcome::Consumed
            },
            "--daemonize" => {
                self.daemonize = true;
                OptionParseOutcome::Consumed
            },
            _ => OptionParseOutcome::Ignored,
        }
    }
}
