use lazy_static::lazy_static;
use regex::Regex;
use std::str::FromStr;

#[derive(Eq, PartialEq, PartialOrd)]
pub struct Ipv4Cidr {
    net: u32,
    mask: u8,
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
        Ok(Ipv4Cidr { net, mask })
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
        let a1 = self.net & 0xFF;
        let a2 = (self.net >> 8) & 0xFF;
        let a3 = (self.net >> 16) & 0xFF;
        let a4 = (self.net >> 24) & 0xFF;
        format!("{}.{}.{}.{}/{}", a4, a3, a2, a1, self.mask)
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
    }
}
