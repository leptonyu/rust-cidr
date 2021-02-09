use actix_web::{get, web, App, HttpServer, Responder};
use cidr::ipv4::Ipv4Cidr;
use cidr::ipv4::Ipv4CidrList;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[get("/{id}/{name}/index.html")]
async fn index(web::Path((id, name)): web::Path<(u32, String)>) -> impl Responder {
    format!("Hello {}! id:{}", name, id)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(index))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}

pub struct Ipv4CidrRange {
    loc_map: HashMap<u128, String>,
    ip_map: BTreeMap<u32, (Ipv4Cidr, u128)>,
}

impl Ipv4CidrRange {
    pub fn new() -> Self {
        Ipv4CidrRange {
            loc_map: HashMap::new(),
            ip_map: BTreeMap::new(),
        }
    }

    pub fn from_file(file: &str, sep: &str) -> Self {
        let mut r = Ipv4CidrRange::new();
        if let Ok(f) = File::open(file) {
            for line in BufReader::new(f).lines() {
                if let Ok(l) = line {
                    let v: Vec<&str> = l.split(sep).collect();
                    if v.len() > 2 {
                        fn parse_block(f: &str, t: &str) -> Ipv4CidrList {
                            if let (Ok(f), Ok(t)) = (Ipv4Addr::from_str(f), Ipv4Addr::from_str(t)) {
                                return Ipv4CidrList::from_ip_range(f, t);
                            }
                            Ipv4CidrList::new()
                        }
                        for (_, block) in parse_block(v[0], v[1]).into_iter() {
                            r.insert(block, v[2].to_owned());
                        }
                    }
                }
            }
        }
        r
    }

    fn hash(loc: &str) -> u128 {
        let vs = md5::compute(loc).0;
        let mut x = vs[0] as u128;
        for i in 1..16 {
            x <<= 4;
            x += vs[i] as u128;
        }
        x
    }

    pub fn insert(&mut self, cidr: Ipv4Cidr, loc: String) {
        let h = Self::hash(&loc);
        self.loc_map.entry(h).or_insert(loc);
        self.ip_map.insert(u32::from(cidr.first_ip()), (cidr, h));
    }

    pub fn get(&self, ip: &Ipv4Addr) -> Option<String> {
        let mut net = u32::from(ip.clone());
        let mut size = 0;
        loop {
            if let Some((v, h)) = self.ip_map.get(&net) {
                if !v.contains_ip(ip) {
                    return None;
                }
                return self.loc_map.get(h).map(|r| r.to_string());
            }
            if size == 32 {
                return None;
            }
            size += 1;
            net >>= size;
            while net & 1 == 0 {
                net >>= 1;
                size += 1;
                if size == 32 {
                    return None;
                }
            }
            net = (net - 1) << size;
            size += 1;
        }
    }
}
