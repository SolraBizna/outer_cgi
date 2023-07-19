use std::collections::HashMap;

use outer_cgi::IO;

fn init(max_parallelism: u32) {
    eprintln!("outer_cgi demo script started with max parallelism: {}",
              max_parallelism);
}

fn handler(io: &mut dyn IO, env: HashMap<String,String>) -> anyhow::Result<i32> {
    io.write_all(b"Content-type: text/plain; charset=utf-8\n\n\
                   Hello world!\n\n")?;
    let mut kvs: Vec<(String,String)> = env.into_iter().collect();
    kvs.sort_by(|a,b| return a.0.cmp(&b.0));
    for (key, value) in kvs {
        io.write_all(format!("{}={}\n", key, value).as_bytes())?;
    }
    io.flush().unwrap();
    Ok(0)
}

pub fn main() {
    outer_cgi::main(init, handler)
}
