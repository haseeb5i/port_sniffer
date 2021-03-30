extern crate clap;

use clap::{App, Arg};
use std::io::{self, Write};
use std::net::{IpAddr, TcpStream};
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::thread;

const MAX_PORTS: u16 = 65535;

fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr, num_threads: u16) {
    let mut port: u16 = start_port + 1;
    loop {
        match TcpStream::connect((addr, port)) {
            Ok(_) => {
                print!(".");
                io::stdout().flush().unwrap();
                tx.send(port).unwrap();
            }
            Err(_) => {}
        }

        if (MAX_PORTS - port) <= num_threads {
            break;
        }
        port += num_threads;
    }
}

fn main() {
    let matches = App::new("Port Sniffer CLI")
        .version("1.0")
        .author("Kevin K. <kbknapp@gmail.com>")
        .about("Checks out the given ip for all open ports")
        .arg(
            Arg::with_name("ipaddress")
                .long("ipaddr")
                .help("Ip address to sniff ports on")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("threads")
                .long("threads")
                .short("j")
                .help("number of threads to use")
                .takes_value(true),
        )
        .get_matches();

    let addr = matches.value_of("ipaddress").unwrap();
    let num_threads = matches.value_of("threads").unwrap_or("1");
    let num_threads = num_threads.parse::<u16>().unwrap();
    let ipaddr = IpAddr::from_str(&addr).unwrap();
    let (tx, rx) = channel();

    for i in 0..num_threads {
        // this one is different from the one on right, scope
        let tx = tx.clone();

        thread::spawn(move || {
            scan(tx, i, ipaddr, num_threads);
        });
    }

    let mut out = vec![];
    drop(tx);
    for p in rx {
        out.push(p);
    }

    println!("");
    out.sort();
    for v in out {
        println!("{} is open", v);
    }
}

