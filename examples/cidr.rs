use cidr::ipv4::{Ipv4Cidr, Ipv4CidrList};
use clap::Clap;
use std::io::{self, BufRead};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Clap)]
#[clap(version = "0.1.0", author = "Daniel Yu<leptonyu@gmail.com>")]
struct Opts {
    #[clap(short, about("Parse ip ranges instead of cidr blocks."))]
    range_parse: bool,

    #[clap(
        short,
        default_value = "\t",
        about("Only work when -r option is setted.")
    )]
    sep: String,

    #[clap(short, long, about("Count all ip blocks size."))]
    count: bool,
}

fn main() {
    let option = Opts::parse();
    let stdin = io::stdin();
    let mut list = Ipv4CidrList::new();
    let mut rem = Ipv4CidrList::new();
    for line in stdin.lock().lines() {
        if let Ok(l) = line {
            if option.range_parse {
                let v: Vec<&str> = l.split(&option.sep).collect();
                if v.len() >= 2 {
                    fn parse_block(f: &str, t: &str) -> Ipv4CidrList {
                        if let (Ok(f), Ok(t)) = (Ipv4Addr::from_str(f), Ipv4Addr::from_str(t)) {
                            return Ipv4CidrList::from_ip_range(f, t);
                        }
                        Ipv4CidrList::new()
                    }
                    for (_, block) in parse_block(v[0], v[1]).into_iter() {
                        list.insert(block);
                    }
                }
            } else {
                fn add(list: &mut Ipv4CidrList, ip: &str) {
                    if let Ok(ip) = Ipv4Cidr::from_str(ip.trim()) {
                        list.insert(ip);
                    }
                }
                match &l.strip_prefix("-") {
                    Some(ip) => add(&mut rem, ip),
                    _ => add(&mut list, &l),
                }
            }
        }
    }
    for (_, cidr) in rem {
        list.remove(&cidr);
    }

    if option.count {
        print!("{}", list.count());
        return;
    }

    print!("{}", list);
}
