//! INMAP Core - High performance network assessment, CIDR intelligence, and port scanning engine.

pub mod cidr;
pub mod scanner;

pub use cidr::{Ipv4Cidr, ProviderCategory, ProviderIntel, RadixIntel};
pub use scanner::{guess_service_name, scan_port, scan_ports_sequential, PortResult};

pub const VERSION: &str = "1.0.0";
