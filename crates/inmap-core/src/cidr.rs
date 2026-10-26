//! High-performance IP classification and CIDR matching.

use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderCategory {
    Cdn,
    Cloud,
    Datacenter,
    Private,
    Loopback,
    Public,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIntel {
    pub provider: &'static str,
    pub category: ProviderCategory,
    pub asn_org: &'static str,
}

#[derive(Debug, Clone)]
pub struct Ipv4Cidr {
    pub network: u32,
    pub mask: u32,
    pub intel: ProviderIntel,
}

impl Ipv4Cidr {
    pub fn new(addr: Ipv4Addr, prefix: u8, intel: ProviderIntel) -> Self {
        assert!(prefix <= 32);
        let mask = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        let network = u32::from(addr) & mask;
        Self { network, mask, intel }
    }

    #[inline]
    pub fn matches(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask) == self.network
    }
}

pub struct RadixIntel {
    entries: Vec<Ipv4Cidr>,
}

impl RadixIntel {
    pub fn new_builtin() -> Self {
        let mut entries = Vec::new();

        // Cloudflare
        let cf_intel = ProviderIntel {
            provider: "Cloudflare",
            category: ProviderCategory::Cdn,
            asn_org: "Cloudflare, Inc.",
        };
        for (ip, prefix) in &[
            (Ipv4Addr::new(173, 245, 48, 0), 20),
            (Ipv4Addr::new(103, 21, 244, 0), 22),
            (Ipv4Addr::new(103, 22, 200, 0), 22),
            (Ipv4Addr::new(104, 16, 0, 0), 13),
            (Ipv4Addr::new(172, 64, 0, 0), 13),
            (Ipv4Addr::new(198, 41, 128, 0), 17),
        ] {
            entries.push(Ipv4Cidr::new(*ip, *prefix, cf_intel.clone()));
        }

        // AWS
        let aws_intel = ProviderIntel {
            provider: "AWS",
            category: ProviderCategory::Cloud,
            asn_org: "Amazon.com, Inc.",
        };
        for (ip, prefix) in &[
            (Ipv4Addr::new(3, 0, 0, 0), 9),
            (Ipv4Addr::new(52, 0, 0, 0), 11),
            (Ipv4Addr::new(54, 0, 0, 0), 8),
        ] {
            entries.push(Ipv4Cidr::new(*ip, *prefix, aws_intel.clone()));
        }

        // DigitalOcean
        let do_intel = ProviderIntel {
            provider: "DigitalOcean",
            category: ProviderCategory::Cloud,
            asn_org: "DigitalOcean, LLC",
        };
        for (ip, prefix) in &[
            (Ipv4Addr::new(104, 131, 0, 0), 16),
            (Ipv4Addr::new(138, 68, 0, 0), 16),
            (Ipv4Addr::new(159, 65, 0, 0), 16),
        ] {
            entries.push(Ipv4Cidr::new(*ip, *prefix, do_intel.clone()));
        }

        Self { entries }
    }

    pub fn classify(&self, ip: IpAddr) -> ProviderIntel {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() {
                    return ProviderIntel {
                        provider: "Localhost",
                        category: ProviderCategory::Loopback,
                        asn_org: "Loopback Interface",
                    };
                }
                if v4.is_private() {
                    return ProviderIntel {
                        provider: "Private RFC1918",
                        category: ProviderCategory::Private,
                        asn_org: "Private Network",
                    };
                }
                for entry in &self.entries {
                    if entry.matches(v4) {
                        return entry.intel.clone();
                    }
                }
                ProviderIntel {
                    provider: "Public / Other",
                    category: ProviderCategory::Public,
                    asn_org: "Unknown ASN",
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return ProviderIntel {
                        provider: "Localhost",
                        category: ProviderCategory::Loopback,
                        asn_org: "Loopback Interface",
                    };
                }
                ProviderIntel {
                    provider: "Public / Other",
                    category: ProviderCategory::Public,
                    asn_org: "Unknown IPv6 ASN",
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_matching() {
        let intel = RadixIntel::new_builtin();
        let cf_ip: IpAddr = "104.16.2.1".parse().unwrap();
        let res = intel.classify(cf_ip);
        assert_eq!(res.provider, "Cloudflare");
        assert_eq!(res.category, ProviderCategory::Cdn);

        let private_ip: IpAddr = "192.168.1.1".parse().unwrap();
        let res_priv = intel.classify(private_ip);
        assert_eq!(res_priv.category, ProviderCategory::Private);

        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let res_loop = intel.classify(loopback);
        assert_eq!(res_loop.category, ProviderCategory::Loopback);
    }
}
