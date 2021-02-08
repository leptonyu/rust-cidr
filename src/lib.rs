//! Utilities for CIDR manipulation.
//!
//! Cidr provides utilities to convert CIDR from/to string, u32 and ip ranges.
//!
//! `Ipv4CidrList` is a collection of CIDRs, it keeps CIDR in order, and can merge newly inserted CIDRs.
//!
//! ```
//!   let mut list = Ipv4CidrList::new();
//!   list.insert(Ipv4Cidr::from_str("0.0.0.0/1").unwrap());
//!   list.insert(Ipv4Cidr::from_str("128.0.0.0/2").unwrap());
//!   list.insert(Ipv4Cidr::from_str("192.0.0.0/2").unwrap());
//!   println!("{}", &list); //0.0.0.0/0
//! ```
//!
//! Parse from ip range:
//!
//! ```
//!   let from = Ipv4Addr::from_str("1.0.0.0").unwrap();
//!   let to = Ipv4Addr::from_str("1.0.0.255").unwrap();
//!   let list = Ipv4CidrList::from_range(u32::from(from), u32::from(to));
//!   println!("{}", &list); //1.0.0.0/24
//! ```

#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

pub mod ipv4;
