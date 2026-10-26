//! High-performance TCP port scanner and service identification engine.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use std::io::{Read, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortResult {
    pub port: u16,
    pub is_open: bool,
    pub service: &'static str,
    pub banner: String,
}

pub fn guess_service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        1433 => "ms-sql-s",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "unknown",
    }
}

pub fn scan_port(ip: IpAddr, port: u16, timeout: Duration) -> PortResult {
    let addr = SocketAddr::new(ip, port);
    let mut banner = String::new();
    let service = guess_service_name(port);

    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(800)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(800)));

            if port == 80 || port == 8080 {
                let req = format!("HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", ip);
                let _ = stream.write_all(req.as_bytes());
            } else if port == 6379 {
                let _ = stream.write_all(b"PING\r\n");
            }

            let mut buf = [0u8; 256];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                }
            }

            PortResult {
                port,
                is_open: true,
                service,
                banner,
            }
        }
        Err(_) => PortResult {
            port,
            is_open: false,
            service,
            banner: String::new(),
        },
    }
}

pub fn scan_ports_sequential(ip: IpAddr, ports: &[u16], timeout: Duration) -> Vec<PortResult> {
    ports
        .iter()
        .map(|&p| scan_port(ip, p, timeout))
        .filter(|res| res.is_open)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guess_service_name() {
        assert_eq!(guess_service_name(22), "ssh");
        assert_eq!(guess_service_name(80), "http");
        assert_eq!(guess_service_name(3306), "mysql");
        assert_eq!(guess_service_name(6379), "redis");
        assert_eq!(guess_service_name(54321), "unknown");
    }

    #[test]
    fn test_scan_closed_port() {
        // Port 1 on 127.0.0.1 is almost certainly closed
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let res = scan_port(ip, 1, Duration::from_millis(50));
        assert_eq!(res.port, 1);
        assert!(!res.is_open);
    }
}
