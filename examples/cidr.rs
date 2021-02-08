use cidr::ipv4::{Ipv4Cidr, Ipv4CidrList};
use clap::Clap;
use std::io::{self, BufRead};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Clap)]
#[clap(author = "Daniel Yu")]
struct Opts {
    #[clap(short)]
    range: bool,

    #[clap(short, long, default_value = "\t")]
    sep: String,

    #[clap(short)]
    count: bool,
}

fn main() {
    let option = Opts::parse();
    let stdin = io::stdin();
    let mut list = Ipv4CidrList::new();
    let mut rem = Ipv4CidrList::new();
    for line in stdin.lock().lines() {
        if let Ok(l) = line {
            if option.range {
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
