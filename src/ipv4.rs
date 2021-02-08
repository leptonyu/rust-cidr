//! Ipv4 CIDR functions
//!
//! This module provides:
//!
//! * [`Ipv4Cidr`] Ipv4 CIDR structure.
//! * [`Ipv4CidrList`] Ipv4 CIDR collection structure.
//!
//!

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::btree_map::Iter;
use std::collections::btree_map::IterMut;
use std::collections::LinkedList;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::net::Ipv4Addr;
use std::str::FromStr;

use std::collections::BTreeMap;
use std::collections::HashSet;

/// Ipv4 CIDR structure
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Ipv4Cidr {
    /// First IP
    net: u32,
    /// Size of CIDR blocks in 2^size.
    size: u8,
}

const NOT_POSSIBLE: &str = "Not possible";

impl Ipv4Cidr {
    /// Create CIDR from ip and mask.
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

    /// Create CIDR from ip and mask
    pub fn from_ip(ip: Ipv4Addr, mask: u8) -> Result<Self, String> {
        Self::new(u32::from(ip), mask)
    }

    /// Get the first ip in the CIDR blocks.
    pub fn first_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.net)
    }

    /// Get the last ip in the CIDR blocks.
    pub fn last_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.to_range().1)
    }

    /// Get the mask
    pub fn mask(&self) -> u8 {
        32 - self.size
    }

    /// Check if the ip is in this CIDR block.
    pub fn contains_ip(&self, ip: &Ipv4Addr) -> bool {
        if self.size == 32 {
            return true;
        }
        self.net >> self.size == u32::from(ip.clone()) >> self.size
    }

    /// Check if the current CIDR block contains other CIDR block.
    pub fn contains_cidr(&self, cidr: &Ipv4Cidr) -> bool {
        if self.size == 32 {
            return true;
        }
        if self.size < cidr.size {
            return false;
        }
        self.net >> self.size == cidr.net >> self.size
    }

    /// Convert CIDR block to u32 range.
    pub fn to_range(&self) -> (u32, u32) {
        if self.size == 32 {
            return (0, u32::MAX);
        }
        (self.net, self.net + (2u32.pow(self.size as u32) - 1))
    }
    /// Convert CIDR block toipo range.
    pub fn to_ip_range(&self) -> (Ipv4Addr, Ipv4Addr) {
        let (f, t) = self.to_range();
        (Ipv4Addr::from(f), Ipv4Addr::from(t))
    }
}

impl FromStr for Ipv4Cidr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref RE: Regex = Regex::new(
                r"^((1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])(\.(1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])){3})(/([0-9]|[12][0-9]|3[012]))?$"
            )
            .expect(NOT_POSSIBLE);
        }

        match RE.captures(s) {
            Some(ref v) => {
                let ms = match v.get(6) {
                    Some(v) => v.as_str().parse::<u8>().expect(NOT_POSSIBLE),
                    _ => 32,
                };
                let ip =
                    Ipv4Addr::from_str(v.get(1).expect(NOT_POSSIBLE).as_str()).expect(NOT_POSSIBLE);
                Ipv4Cidr::new(u32::from(ip), ms)
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
        Ipv4Cidr::new(addr, 32).expect(NOT_POSSIBLE)
    }
}

impl Display for Ipv4Cidr {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}/{}", self.first_ip(), self.mask())
    }
}

/// Ipv4 CIDR collection structure.
#[derive(Eq, PartialEq, Clone)]
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
    /// Create empty collection.
    pub fn new() -> Self {
        Ipv4CidrList {
            inner: BTreeMap::new(),
        }
    }

    /// Generate collection from ip range, can result multiple CIDR blocks.
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
                Ipv4Cidr::new(if m == 32 { 0 } else { f << m }, 32 - m).expect(NOT_POSSIBLE);
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

    /// Generate collection from ip range, can result multiple CIDR blocks.
    pub fn from_ip_range(from: Ipv4Addr, to: Ipv4Addr) -> Self {
        Self::from_range(u32::from(from), u32::from(to))
    }

    /// Iterate all CIDR blocks.
    pub fn iter(&self) -> Iter<'_, u32, Ipv4Cidr> {
        self.inner.iter()
    }

    /// Iterate all mutable CIDR blocks.
    pub fn iter_mut(&mut self) -> IterMut<'_, u32, Ipv4Cidr> {
        self.inner.iter_mut()
    }

    /// Export CIDR blocks to ip ranges, normally ip ranges item size is smaller than CIDR blocks.
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

    /// Check if collection contains ip.
    pub fn contains_ip(&self, ip: &Ipv4Addr) -> bool {
        self.contains_cidr(&Ipv4Cidr::from(ip.clone()))
    }

    /// Check if collection contains CIDR block.
    pub fn contains_cidr(&self, cidr: &Ipv4Cidr) -> bool {
        self.search_parent(cidr).is_some()
    }

    /// Get the parent CIDR block with specified CIDR block.
    pub fn search_parent(&self, cidr: &Ipv4Cidr) -> Option<&Ipv4Cidr> {
        let mut net = cidr.net;
        let mut size = cidr.size;
        loop {
            if let Some(v) = self.inner.get(&net) {
                if v.size >= size {
                    return Some(v);
                }
            }
            if size == 32 {
                return None;
            }
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

    fn delete_in_range(&mut self, cidr: &Ipv4Cidr) -> bool {
        let (f, t) = cidr.to_range();
        let mut rem = LinkedList::new();
        for (&k, v) in self.inner.range(f..=t) {
            if cidr.contains_cidr(v) {
                rem.push_back(k);
            }
        }
        let changed = !rem.is_empty();
        for k in rem {
            self.inner.remove(&k);
        }
        changed
    }

    /// Insert a CIDR block into the collection. Return `true` means collection is modified.
    pub fn insert(&mut self, mut cidr: Ipv4Cidr) -> bool {
        self.delete_in_range(&cidr);
        if self.contains_cidr(&cidr) {
            return false;
        }
        loop {
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
                        cidr = Ipv4Cidr::new(pair, 31 - cidr.size).expect(NOT_POSSIBLE);
                        continue;
                    }
                }
            }
            self.inner.insert(cidr.net, cidr);
            return true;
        }
    }

    /// Remove CIDR blocks.
    pub fn remove(&mut self, cidr: &Ipv4Cidr) -> bool {
        if self.delete_in_range(cidr) {
            return true;
        }
        let mut add = HashSet::new();
        if let Some(v) = self.search_parent(cidr) {
            if v == cidr {
                return false;
            }
            let v = v.clone();
            self.inner.remove(&v.net);
            let (a2, a3) = cidr.to_range();
            let (a1, a4) = v.to_range();
            if a1 < a2 {
                add.insert((a1, a2 - 1));
            }
            if a3 < a4 {
                add.insert((a3 + 1, a4));
            }
        }
        for (a, b) in add {
            for (_, v) in Self::from_range(a, b) {
                self.insert(v);
            }
        }
        true
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
        // println!("{}", &list);
        assert_eq!(3, list.inner.len());
    }
    #[test]
    fn range_parse_tests() {
        let from = Ipv4Addr::from_str("1.0.0.0").unwrap();
        let to = Ipv4Addr::from_str("1.0.0.255").unwrap();
        let list = Ipv4CidrList::from_ip_range(from, to);
        // println!("{}", list.to_string());
        assert_eq!("1.0.0.0/24", list.to_string().trim());

        let from = Ipv4Addr::from_str("0.0.0.0").unwrap();
        let to = Ipv4Addr::from_str("255.255.255.255").unwrap();
        let list = Ipv4CidrList::from_ip_range(from, to);
        assert_eq!("0.0.0.0/0", list.to_string().trim());

        // let list = Ipv4CidrList::from_range(0, u32::MAX - 1);
        // println!("{}", &list)
    }

    #[test]
    fn remove_cidr_tests() {
        let from = Ipv4Addr::from_str("0.0.0.0").unwrap();
        let to = Ipv4Addr::from_str("255.255.255.255").unwrap();
        let rem = Ipv4Cidr::from_str("127.0.0.0/8").unwrap();
        let mut list = Ipv4CidrList::from_ip_range(from, to);
        list.remove(&rem);

        // let list = Ipv4CidrList::from_range(0, 0);
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

    #[quickcheck]
    fn check_cidr_list_remove(from: u32, to: u32, rem: u32, m: u8) -> bool {
        let c = Ipv4Cidr::new(rem, m % 33).unwrap();
        let d = c.clone();
        let mut list = Ipv4CidrList::from_range(from, to);
        let mut modl = list.clone();
        if modl.remove(&c) {
            assert_eq!(true, modl.insert(c));
            list.insert(d);
        }
        list == modl
    }
}
