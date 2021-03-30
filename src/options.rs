#[cfg(unix)]
use crate::unix;
use std;
use std::io;
use std::slice::Iter;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::collections::HashMap;
use super::Listener;

/// Used internally.
pub enum OptionParseOutcome {
    Consumed, Failed, Ignored
}

/// Used internally.
pub trait OptionHandler {
    /// Consume an option if you recognize it. You may consume additional
    /// arguments via the iterator.
    fn maybe_parse_option<'a>(&mut self, arg: &str, it: &mut Iter<String>)
                              -> OptionParseOutcome;
}

#[allow(unused)]
pub struct NullOSOptions {}
impl OptionHandler for NullOSOptions {
    fn maybe_parse_option<'a>(&mut self, _: &str, _: &mut Iter<String>)
                              -> OptionParseOutcome {
        OptionParseOutcome::Ignored
    }
}
#[allow(unused)]
impl NullOSOptions {
    pub fn post_setup(self) -> io::Result<()> { Ok(()) }
}

pub fn fix_fds(env: &HashMap<String,String>) -> Option<Box<dyn Listener>> {
    #[cfg(unix)] return unix::fix_fds(env);
    #[cfg(not(unix))] return None;
}

pub fn print_usage() {
    let app_name = std::env::args().next()
        .unwrap_or_else(|| "outer_cgi".to_string());
    eprintln!(r#"
Usage: configure this program to be run directly as either CGI or FCGI.

== OR ==

Usage: {} fcgi-tcp --bind ADDR:PORT [options]

Run as an FCGI server, listening on the specified address and port. If you will
be listening on a non-localhost address, consider adding each allowed web
server address to FCGI_WEB_SERVER_ADDRS for security purposes. (Also bear in
mind that trusting the integrity of your IP network is not as safe as you might
believe...)

All FCGI options are accepted."#, &app_name);
    #[cfg(unix)] eprintln!(r#"
== OR ==

Usage: {} fcgi-unix --bind SOCKPATH [options]

Runs as an FCGI server, creating and listening on the specified UNIX socket(s).

All FCGI options are accepted, along with:

--chown <UID>:
    Make the socket have the specified owner.
--chgrp <GID>:
    Make the socket have the specified group.
--chmod <MODE>:
    Make the socket have the specified permissions, in octal. Default: 660.

Note: If you are using POSIX ACLs, please manually check to ensure that these
options are doing what you want.
"#, &app_name);
    eprintln!(r#"## FCGI OPTIONS ##

--max-connections <NUM>:
    Limit the maximum number of FCGI connections that will be handled
    simultaneously. There is a moderate memory cost for setting this value too
    high. Default: 10.
"#);
    #[cfg(unix)] eprintln!(r#"## UNIX-SPECIFIC OPTIONS ##

--chroot <PATH>:
--setuid <UID>:
--setgid <GID>:
    Drop privileges after setting up the sockets. (Note that only the FCGI
    sockets will be set up; if the application, for instance, requires a
    database connection, make sure it can access the database with its new
    privileges!)

--syslog <IDENTIFIER>:
    Redirect errors after initial setup to syslog, with the specified
    identifier.

--daemonize:
    Go into the background after initial setup. This requires /dev/null to
    exist. You should either redirect stderr somewhere useful or use the
    --syslog option.
"#);
}

pub trait AddressType: Sized {
    fn parse_address(addr: &str) -> Option<Self>;
}
impl AddressType for SocketAddr {
    fn parse_address(addr: &str) -> Option<SocketAddr> {
        addr.parse().ok()
    }
}
impl AddressType for PathBuf {
    fn parse_address(addr: &str) -> Option<PathBuf> {
        Some(PathBuf::from(addr))
    }
}

pub struct BindOptions<T> {
    pub addr: Option<T>,
}
impl<T> BindOptions<T> {
    pub fn new() -> BindOptions<T> { BindOptions { addr: None } }
}
impl<T: AddressType> OptionHandler for BindOptions<T> {
    fn maybe_parse_option<'a>(&mut self, arg: &str, it: &mut Iter<String>)
                              -> OptionParseOutcome {
        match arg {
            "--bind" => {
                if self.addr.is_some() {
                    it.next(); // skip the next argument, if any
                    eprintln!("More than one --bind specified");
                    return OptionParseOutcome::Failed
                }
                let addr = match it.next() {
                    Some(addr) => addr,
                    None => {
                        eprintln!("Missing argument for --bind");
                        return OptionParseOutcome::Failed
                    },
                };
                match T::parse_address(addr) {
                    None => {
                        eprintln!("Invalid argument for --bind");
                        return OptionParseOutcome::Failed
                    },
                    Some(addr) => {
                        self.addr = Some(addr);
                        OptionParseOutcome::Consumed
                    }
                }
            },
            _ => OptionParseOutcome::Ignored
        }
    }
}

/// Handles the whole command line. Returns true if the whole command line was
/// valid, false otherwise.
pub fn handle_command_line<'a>(handlers: &mut [&mut dyn OptionHandler],
                               cmdline: Iter<String>) -> bool {
    let mut next = cmdline;
    let mut ok = true;
    'outer: while let Some(arg) = next.next() {
        for h in handlers.iter_mut() {
            let result = h.maybe_parse_option(arg, &mut next);
            match result {
                OptionParseOutcome::Consumed => continue 'outer,
                OptionParseOutcome::Ignored => (),
                OptionParseOutcome::Failed => { ok = false; continue 'outer }
            }
        }
        eprintln!("Unhandled option: {}", arg);
        ok = false;
    }
    ok
}

#[cfg(unix)]
pub fn os_options() -> unix::UnixOSOptions { unix::UnixOSOptions::new() }
#[cfg(not(unix))]
pub fn os_options() -> NullOSOptions { NullOSOptions {} }
