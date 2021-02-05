use cidr_cli::ipv4::{Ipv4Cidr, Ipv4CidrList};
use std::io::{self, BufRead};
use std::str::FromStr;

fn main() {
    let stdin = io::stdin();
    let mut list = Ipv4CidrList::new();
    for line in stdin.lock().lines() {
        if let Ok(l) = line {
            if let Ok(ip) = Ipv4Cidr::from_str(&l) {
                list.push(ip);
            }
        }
    }
    print!("{}", list);
}
