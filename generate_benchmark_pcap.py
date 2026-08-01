#!/usr/bin/env python3
"""
Generate a large PCAP file for benchmarking single-threaded vs multi-threaded DPI performance.
"""

import struct
import random
import sys

class PCAPWriter:
    def __init__(self, filename):
        self.file = open(filename, 'wb')
        self.write_global_header()
        self.timestamp = 1700000000

    def write_global_header(self):
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)

    def write_packet(self, data):
        ts_sec = self.timestamp
        ts_usec = random.randint(0, 999999)
        self.timestamp += 1

        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)

    def close(self):
        self.file.close()


def create_ethernet_header(src_mac, dst_mac, ethertype=0x0800):
    return bytes.fromhex(dst_mac.replace(':', '')) + \
           bytes.fromhex(src_mac.replace(':', '')) + \
           struct.pack('>H', ethertype)


def create_ip_header(src_ip, dst_ip, protocol, payload_len):
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(1, 65535)
    flags_frag = 0x4000
    ttl = 64
    checksum = 0

    header = struct.pack('>BBHHHBBH',
                         version_ihl, tos, total_len,
                         ident, flags_frag,
                         ttl, protocol, checksum)

    header += bytes([int(x) for x in src_ip.split('.')])
    header += bytes([int(x) for x in dst_ip.split('.')])

    return header


def create_tcp_header(src_port, dst_port, seq, ack, flags, payload_len=0):
    data_offset = 5 << 4
    window = 65535
    checksum = 0
    urgent = 0

    return struct.pack('>HHIIBBHHH',
                       src_port, dst_port,
                       seq, ack,
                       data_offset, flags,
                       window, checksum, urgent)


def create_tls_client_hello(sni):
    sni_bytes = sni.encode('ascii')
    sni_entry = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list

    supported_versions = struct.pack('>HHB', 0x002b, 3, 2) + struct.pack('>H', 0x0304)

    extensions = sni_ext + supported_versions
    extensions_data = struct.pack('>H', len(extensions)) + extensions

    client_version = struct.pack('>H', 0x0303)
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    session_id = struct.pack('B', 0)
    cipher_suites = struct.pack('>H', 4) + struct.pack('>HH', 0x1301, 0x1302)
    compression = struct.pack('BB', 1, 0)

    client_hello_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_data

    handshake = struct.pack('B', 0x01)
    handshake += struct.pack('>I', len(client_hello_body))[1:]
    handshake += client_hello_body

    record = struct.pack('B', 0x16)
    record += struct.pack('>H', 0x0301)
    record += struct.pack('>H', len(handshake))
    record += handshake

    return record


def random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def random_mac():
    return ':'.join(f"{random.randint(0,255):02x}" for _ in range(6))


def main():
    num_connections = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'benchmark.pcap'

    writer = PCAPWriter(output_file)

    domains = [
        'www.google.com', 'www.youtube.com', 'www.facebook.com',
        'www.instagram.com', 'twitter.com', 'www.amazon.com',
        'www.netflix.com', 'github.com', 'discord.com', 'zoom.us',
        'www.tiktok.com', 'open.spotify.com', 'www.cloudflare.com',
        'www.microsoft.com', 'www.apple.com', 'www.reddit.com',
        'www.wikipedia.org', 'www.linkedin.com'
    ]

    user_mac = '00:11:22:33:44:55'
    gateway_mac = 'aa:bb:cc:dd:ee:ff'
    seq_base = 1000

    for i in range(num_connections):
        user_ip = random_ip()
        dst_ip = random_ip()
        sni = random.choice(domains)
        src_port = random.randint(49152, 65535)
        dst_port = 443

        # SYN
        eth = create_ethernet_header(user_mac, gateway_mac)
        tcp = create_tcp_header(src_port, dst_port, seq_base, 0, 0x02)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)

        # SYN-ACK
        tcp = create_tcp_header(dst_port, src_port, seq_base + 1000, seq_base + 1, 0x12)
        ip = create_ip_header(dst_ip, user_ip, 6, len(tcp))
        eth2 = create_ethernet_header(gateway_mac, user_mac)
        writer.write_packet(eth2 + ip + tcp)

        # ACK
        tcp = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x10)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)

        # Client Hello (the actual DPI target)
        tls_data = create_tls_client_hello(sni)
        tcp = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x18)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(tls_data))
        writer.write_packet(eth + ip + tcp + tls_data)

        seq_base += 10000

        if (i + 1) % 1000 == 0:
            print(f"  Generated {i + 1}/{num_connections} connections...")

    writer.close()
    print(f"\nDone. Wrote {num_connections} connections (~{num_connections * 4} packets) to {output_file}")


if __name__ == '__main__':
    main()