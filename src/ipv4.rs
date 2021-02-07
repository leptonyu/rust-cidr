use lazy_static::lazy_static;
use regex::Captures;
use regex::Regex;
use std::collections::btree_map::Iter;
use std::collections::btree_map::IterMut;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::net::Ipv4Addr;
use std::str::FromStr;

use std::collections::BTreeMap;
use std::collections::HashSet;

#[derive(Eq, PartialEq, Debug)]
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

    pub fn first_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.net)
    }
    pub fn last_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.to_range().1)
    }

    pub fn mask(&self) -> u8 {
        32 - self.size
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

    pub fn to_range(&self) -> (u32, u32) {
        if self.size == 32 {
            return (0, u32::MAX);
        }
        (self.net, self.net + (2u32.pow(self.size as u32) - 1))
    }
}

impl FromStr for Ipv4Cidr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref RE: Regex = Regex::new(
                r"^(1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.(1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])(/([0-9]|[12][0-9]|3[012]))?$"
            )
            .expect("Not possible");
        }
        fn parse_u32<'t>(ind: usize, v: &Captures<'t>) -> Result<u32, String> {
            v.get(ind)
                .map(|r| r.as_str().parse::<u32>())
                .ok_or("Not possible")?
                .map_err(|e| e.to_string())
        }

        match RE.captures(s) {
            Some(ref v) => {
                let ms = match v.get(6) {
                    Some(v) => v.as_str().parse::<u8>().expect("Not possible"),
                    _ => 32,
                };
                Ipv4Cidr::new(
                    (parse_u32(1, v)? << 24)
                        + (parse_u32(2, v)? << 16)
                        + (parse_u32(3, v)? << 8)
                        + parse_u32(4, v)?,
                    ms,
                )
            }
            _ => Err("Invalid CIDR format.".to_owned()),
        }
    }
}

impl From<Ipv4Addr> for Ipv4Cidr {
    fn from(addr: Ipv4Addr) -> Self {
        Ipv4Cidr::from(u32::from(addr))
    }
}

impl From<u32> for Ipv4Cidr {
    fn from(addr: u32) -> Self {
        Ipv4Cidr::new(addr, 32).expect("Not possible")
    }
}

impl Display for Ipv4Cidr {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}/{}", self.first_ip(), self.mask())
    }
}

pub struct Ipv4CidrList {
    inner: BTreeMap<u32, Ipv4Cidr>,
}

impl Display for Ipv4CidrList {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        for (&_, v) in self.inner.iter() {
            write!(f, "{}\n", v.to_string())?;
        }
        Ok(())
    }
}

impl IntoIterator for Ipv4CidrList {
    type Item = (u32, Ipv4Cidr);
    type IntoIter = std::collections::btree_map::IntoIter<u32, Ipv4Cidr>;
    fn into_iter(self) -> <Self as IntoIterator>::IntoIter {
        self.inner.into_iter()
    }
}

impl Ipv4CidrList {
    pub fn new() -> Self {
        Ipv4CidrList {
            inner: BTreeMap::new(),
        }
    }

    pub fn from_range(from: u32, to: u32) -> Self {
        let mut list = Ipv4CidrList::new();
        if from > to {
            return list;
        }
        fn build(from: u32, to: u32, list: &mut Ipv4CidrList) {
            let mut f = from;
            let mut t = to;
            let mut m = 0;
            while f != t {
                f >>= 1;
                t >>= 1;
                m += 1;
            }
            let block =
                Ipv4Cidr::new(if m == 32 { 0 } else { f << m }, 32 - m).expect("Not possible");
            if block.to_range() == (from, to) {
                list.insert(block);
                return;
            }
            let mid = (f << 1) + 1 << m - 1;
            build(from, mid - 1, list);
            build(mid, to, list);
        }
        build(from, to, &mut list);
        list
    }

    pub fn iter(&self) -> Iter<'_, u32, Ipv4Cidr> {
        self.inner.iter()
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, u32, Ipv4Cidr> {
        self.inner.iter_mut()
    }

    pub fn to_range(&self) -> Vec<(Ipv4Addr, Ipv4Addr)> {
        let mut v = vec![];
        let mut iter = self.iter();
        let mut f;
        if let Some((_, cidr)) = iter.next() {
            f = cidr.to_range();
        } else {
            return v;
        }
        while let Some((_, cidr)) = iter.next() {
            let t = cidr.to_range();
            if t.0 == f.1 + 1 {
                f.1 = t.1;
            } else {
                v.push((Ipv4Addr::from(f.0), Ipv4Addr::from(f.1)));
            }
        }
        v.push((Ipv4Addr::from(f.0), Ipv4Addr::from(f.1)));
        v
    }

    pub fn insert(&mut self, mut cidr: Ipv4Cidr) {
        loop {
            let mut rem = HashSet::new();
            //Search
            for (&k, v) in self.inner.iter() {
                if v.contains_cidr(&cidr) {
                    return;
                }
                if cidr.contains_cidr(v) {
                    rem.insert(k);
                }
            }
            //Remove
            for k in rem {
                self.inner.remove(&k);
            }
            //Merge
            if cidr.size < 32 {
                let block = cidr.net >> cidr.size;
                let pair = if block & 1 == 0 {
                    (block + 1) << cidr.size
                } else {
                    (block - 1) << cidr.size
                };
                if let Some(v) = self.inner.get(&pair) {
                    if v.size == cidr.size {
                        self.inner.remove(&pair);
                        cidr = Ipv4Cidr::new(pair, 31 - cidr.size).expect("Not possible");
                        continue;
                    }
                }
            }
            self.inner.insert(cidr.net, cidr);
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;
    #[test]
    fn block_parse_tests() {
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
    #[test]
    fn block_list_tests() {
        let mut list = Ipv4CidrList::new();
        list.insert(Ipv4Cidr::from_str("0.0.0.0/1").unwrap());
        list.insert(Ipv4Cidr::from_str("128.0.0.0/1").unwrap());
        assert_eq!(1, list.inner.len());

        let mut list = Ipv4CidrList::new();
        list.insert(Ipv4Cidr::from_str("0.0.0.0/1").unwrap());
        list.insert(Ipv4Cidr::from_str("128.0.0.0/2").unwrap());
        list.insert(Ipv4Cidr::from_str("192.0.0.0/2").unwrap());
        assert_eq!(1, list.inner.len());
        // println!("{}", &list);

        let mut list = Ipv4CidrList::new();
        list.insert(Ipv4Cidr::from_str("4.0.0.0/8").unwrap());
        list.insert(Ipv4Cidr::from_str("5.61.0.0/16").unwrap());
        list.insert(Ipv4Cidr::from_str("6.0.0.0/7").unwrap());
        assert_eq!(3, list.inner.len());
        // println!("{}", &list);
    }
    #[test]
    fn range_parse_tests() {
        let from = Ipv4Addr::from_str("1.0.0.0").unwrap();
        let to = Ipv4Addr::from_str("1.0.0.255").unwrap();
        let list = Ipv4CidrList::from_range(u32::from(from), u32::from(to));
        assert_eq!("1.0.0.0/24", list.to_string().trim());
        // println!("{}", list.to_string());

        let from = Ipv4Addr::from_str("0.0.0.0").unwrap();
        let to = Ipv4Addr::from_str("255.255.255.255").unwrap();
        let list = Ipv4CidrList::from_range(u32::from(from), u32::from(to));
        assert_eq!("0.0.0.0/0", list.to_string().trim());

        // let list = Ipv4CidrList::from_range(0, u32::MAX - 1);
        // println!("{}", &list)
    }

    #[quickcheck]
    fn convert_tests(xs: u32, ys: u8) -> bool {
        match Ipv4Cidr::new(xs, ys % 33) {
            Ok(ip) => ip == Ipv4Cidr::from_str(&ip.to_string()).unwrap(),
            _ => false,
        }
    }
    #[quickcheck]
    fn check_contains_ip(ip: u32, i: u8) -> bool {
        Ipv4Cidr::new(ip, i % 33)
            .unwrap()
            .contains_ip(&Ipv4Addr::from(ip))
    }

    #[quickcheck]
    fn check_contains_cidr(ip: u32, i: u8) -> bool {
        let i = i % 32;
        let a0 = Ipv4Cidr::new(ip, i).unwrap();
        let a1 = Ipv4Cidr::new(ip, i + 1).unwrap();
        a0.contains_cidr(&a1) && !a1.contains_cidr(&a0)
    }

    #[quickcheck]
    fn check_to_range(ip: u32, i: u8) -> bool {
        let cidr = Ipv4Cidr::new(ip, i % 32).unwrap();
        let (from, to) = cidr.to_range();
        if from > to {
            return false;
        }
        if cidr.size == 32 {
            return from == 0 && to == u32::MAX;
        }
        let count = to - from + 1;
        count >> cidr.size == 1 && count.count_ones() == 1
    }

    #[quickcheck]
    fn check_cidr_list(ip: u32) -> bool {
        let mut list = Ipv4CidrList::new();
        for j in 1..=32 {
            list.insert(Ipv4Cidr::new(ip, j).unwrap());
        }
        list.inner.len() == 1
    }

    #[quickcheck]
    fn check_cidr_list_change(from: u32, to: u32) -> bool {
        from > to
            || Ipv4CidrList::from_range(from, to).to_range()
                == vec![(Ipv4Addr::from(from), Ipv4Addr::from(to))]
    }
}
