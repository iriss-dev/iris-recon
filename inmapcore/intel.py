"""Offline ASN, Cloud provider and Threat Intelligence IP classification."""
import ipaddress
from typing import Dict, Any, List

# Well-known provider CIDR ranges for fast offline classification.
KNOWN_PROVIDERS = [
    {
        'name': 'Cloudflare',
        'category': 'cdn',
        'asn_org': 'Cloudflare, Inc.',
        'cidrs': [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
            '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
            '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
            '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
            '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32'
        ]
    },
    {
        'name': 'AWS',
        'category': 'cloud',
        'asn_org': 'Amazon.com, Inc.',
        'cidrs': [
            '3.0.0.0/9', '3.128.0.0/9', '13.32.0.0/15', '13.35.0.0/16',
            '13.52.0.0/14', '13.56.0.0/15', '15.197.0.0/16', '18.0.0.0/8',
            '52.0.0.0/11', '52.32.0.0/11', '52.64.0.0/12', '54.0.0.0/8',
            '99.84.0.0/16', '99.86.0.0/16', '143.204.0.0/16', '150.222.0.0/16'
        ]
    },
    {
        'name': 'Google Cloud',
        'category': 'cloud',
        'asn_org': 'Google LLC',
        'cidrs': [
            '34.64.0.0/10', '34.128.0.0/10', '35.184.0.0/13', '35.192.0.0/12',
            '35.208.0.0/12', '35.224.0.0/12', '35.240.0.0/13', '8.8.8.0/24', '8.8.4.0/24'
        ]
    },
    {
        'name': 'Microsoft Azure',
        'category': 'cloud',
        'asn_org': 'Microsoft Corporation',
        'cidrs': [
            '13.64.0.0/11', '13.96.0.0/13', '13.104.0.0/14', '20.0.0.0/11',
            '20.32.0.0/11', '20.64.0.0/10', '20.128.0.0/16', '23.96.0.0/13',
            '40.64.0.0/10', '40.128.0.0/12', '51.140.0.0/14', '52.136.0.0/13',
            '52.145.0.0/16', '52.148.0.0/14', '52.152.0.0/13', '52.160.0.0/11', '52.224.0.0/11'
        ]
    },
    {
        'name': 'DigitalOcean',
        'category': 'cloud',
        'asn_org': 'DigitalOcean, LLC',
        'cidrs': [
            '104.131.0.0/16', '104.236.0.0/16', '104.248.0.0/16', '134.122.0.0/16',
            '134.209.0.0/16', '138.68.0.0/16', '138.197.0.0/16', '142.93.0.0/16',
            '143.110.128.0/17', '143.198.0.0/16', '144.126.192.0/18', '146.190.0.0/16',
            '157.230.0.0/16', '157.245.0.0/16', '159.65.0.0/16', '159.89.0.0/16',
            '159.203.0.0/16', '161.35.0.0/16', '164.90.128.0/17', '164.92.64.0/18',
            '165.22.0.0/16', '165.227.0.0/16', '167.71.0.0/16', '167.99.0.0/16',
            '167.172.0.0/16', '178.62.0.0/16', '178.128.0.0/16', '188.166.0.0/16',
            '188.226.128.0/17', '192.241.128.0/17', '198.199.64.0/18', '198.211.96.0/19',
            '206.189.0.0/16', '206.81.16.0/20', '207.154.192.0/18', '209.97.128.0/17'
        ]
    },
    {
        'name': 'Hetzner',
        'category': 'datacenter',
        'asn_org': 'Hetzner Online GmbH',
        'cidrs': [
            '78.46.0.0/15', '88.198.0.0/16', '94.130.0.0/16', '95.216.0.0/15',
            '116.202.0.0/15', '128.140.0.0/15', '135.181.0.0/16', '136.243.0.0/16',
            '138.201.0.0/16', '142.132.128.0/17', '144.76.0.0/16', '148.251.0.0/16',
            '159.69.0.0/16', '162.55.0.0/16', '168.119.0.0/16', '176.9.0.0/16',
            '188.34.128.0/17', '188.40.0.0/16', '195.201.0.0/16', '213.133.96.0/19', '213.239.192.0/18'
        ]
    },
    {
        'name': 'OVH',
        'category': 'datacenter',
        'asn_org': 'OVH SAS',
        'cidrs': [
            '51.68.0.0/14', '51.75.0.0/16', '51.77.0.0/16', '51.79.0.0/16',
            '51.81.0.0/16', '51.83.0.0/16', '51.89.0.0/16', '51.91.0.0/16',
            '54.36.0.0/15', '54.38.0.0/15', '137.74.0.0/16', '141.94.0.0/15',
            '142.44.128.0/17', '145.239.0.0/16', '147.135.0.0/16', '149.56.0.0/16',
            '151.80.0.0/16', '158.69.0.0/16', '164.132.0.0/16', '167.114.0.0/16',
            '176.31.0.0/16', '178.32.0.0/15', '188.165.0.0/16', '192.95.0.0/18',
            '192.99.0.0/16', '198.27.64.0/18', '198.50.128.0/17', '198.100.144.0/20',
            '198.245.48.0/20', '217.182.0.0/16'
        ]
    }
]

# Pre-parse networks into tuple of (network_obj, provider_dict)
_COMPILED_NETWORKS = []
for p in KNOWN_PROVIDERS:
    for c in p['cidrs']:
        try:
            _COMPILED_NETWORKS.append((ipaddress.ip_network(c, strict=False), p))
        except ValueError:
            pass


def classify_ip(ip_str: str) -> Dict[str, Any]:
    """Classify an IP address by origin, provider, private status, and risk profile."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: '{ip_str}'") from exc

    res = {
        'ip': str(addr),
        'version': addr.version,
        'is_private': addr.is_private,
        'is_loopback': addr.is_loopback,
        'is_multicast': addr.is_multicast,
        'is_reserved': addr.is_reserved,
        'is_link_local': addr.is_link_local,
        'provider': 'Public / Other',
        'category': 'public',
        'asn_org': 'Unknown ASN',
        'risk_tags': []
    }

    if addr.is_loopback:
        res['provider'] = 'Localhost'
        res['category'] = 'loopback'
        res['risk_tags'].append('loopback-interface')
        return res

    if addr.is_private:
        res['provider'] = 'Private RFC1918 / Local'
        res['category'] = 'private'
        res['risk_tags'].append('internal-network')
        return res

    # Check compiled network ranges
    for net, prov in _COMPILED_NETWORKS:
        if addr.version == net.version and addr in net:
            res['provider'] = prov['name']
            res['category'] = prov['category']
            res['asn_org'] = prov['asn_org']
            if prov['category'] == 'cdn':
                res['risk_tags'].append('cdn-edge-proxy')
            elif prov['category'] in ('cloud', 'datacenter'):
                res['risk_tags'].append('direct-cloud-host')
            break

    return res
