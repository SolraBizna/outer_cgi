This crate is a thin CGI/FCGI wrapper for Rust programs. It is *not* a full web framework. You write a Rust program as if it were a CGI, using the provided `stdin`, `stdout`, and `env` replacements. This crate does the work of making it function both as a CGI or as an FCGI, with as much or as little parallelism as called for.

See [the crate documentation](http://doc.rust-lang.org/outer_cgi) for more information.

Unices are explicitly supported, but I have only tested it on Linux. Windows support is present but is entirely untested.

# License

outer_cgi is distributed under the zlib license. The (very brief) text of the license can be found in [`LICENSE.md`](LICENSE.md).
