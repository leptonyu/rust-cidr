use lazy_static::lazy_static;
use regex::Regex;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Eq, PartialEq)]
pub struct Ipv4Cidr {
    net: u32,
    size: u8,
}

impl Ipv4Cidr {
    pub fn new(mut net: u32, mask: u8) -> Result<Self, String> {
        if mask > 32 {
            return Err("Mask should equal or less then 32.".to_string());
        }
        if mask == 0 {
            net = 0
        } else if mask < 32 {
            net = (net >> (32 - mask)) << (32 - mask)
        }
        let size = 32 - mask;
        Ok(Ipv4Cidr { net, size })
    }

    pub fn contains_ip(&self, ip: &Ipv4Addr) -> bool {
        if self.size == 32 {
            return true;
        }
        self.net >> self.size == u32::from(ip.clone()) >> self.size
    }

    pub fn contains_cidr(&self, cidr: &Ipv4Cidr) -> bool {
        if self.size == 32 {
            return true;
        }
        if self.size < cidr.size {
            return false;
        }
        self.net >> self.size == cidr.net >> self.size
    }
}

impl FromStr for Ipv4Cidr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref RE: Regex = Regex::new(
                r"^(1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])(/([0-9]|[12][0-9]|3[012]))?$"
            )
            .unwrap();
        }
        match RE.captures(s) {
            Some(v) => {
                let a1 = v.get(1).unwrap().as_str().parse::<u32>().unwrap();
                let a2 = v.get(2).unwrap().as_str().parse::<u32>().unwrap();
                let a3 = v.get(3).unwrap().as_str().parse::<u32>().unwrap();
                let a4 = v.get(4).unwrap().as_str().parse::<u32>().unwrap();
                let ms = match v.get(6) {
                    Some(v) => v.as_str().parse::<u8>().unwrap(),
                    _ => 32,
                };
                Ipv4Cidr::new((a1 << 24) + (a2 << 16) + (a3 << 8) + a4, ms)
            }
            _ => Err("Invalid CIDR format.".to_owned()),
        }
    }
}

impl ToString for Ipv4Cidr {
    fn to_string(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.net), 32 - self.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;
    #[test]
    fn some_tests() {
        assert_eq!("0.0.0.0/0", Ipv4Cidr::new(0, 0).unwrap().to_string());
        assert_eq!(
            "255.255.255.255/32",
            Ipv4Cidr::new(u32::MAX, 32).unwrap().to_string()
        );
        assert_eq!(
            "127.0.0.0/8",
            Ipv4Cidr::new(127 << 24, 8).unwrap().to_string()
        );
    }

    quickcheck! {
        fn convert_tests(xs: u32, ys: u8) -> bool {
            match Ipv4Cidr::new(xs, ys % 33) {
                Ok(ip) => ip == Ipv4Cidr::from_str(&ip.to_string()).unwrap(),
                _ => false,
            }
        }
        fn check_contains_ip(ip: u32, i: u8) -> bool {
            Ipv4Cidr::new(ip, i % 33).unwrap().contains_ip(&Ipv4Addr::from(ip))
        }
        fn check_contains_cidr(ip: u32, i: u8) -> bool {
            let i = i % 32;
            let a0 = Ipv4Cidr::new(ip, i).unwrap();
            let a1 = Ipv4Cidr::new(ip, i+1).unwrap();
            a0.contains_cidr(&a1) && !a1.contains_cidr(&a0)
        }
    }
}
