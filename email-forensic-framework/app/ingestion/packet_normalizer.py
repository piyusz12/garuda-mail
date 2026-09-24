from scapy.all import Ether, IP, TCP, PcapReader
from app.models.packet import PacketRecord
from datetime import datetime

class PacketNormalizer:
    @staticmethod
    def normalize(pkt) -> PacketRecord | None:
        """Takes a Scapy packet and returns a normalized internal PacketRecord"""
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return None
            
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        
        # MAC Addresses (if available)
        src_mac = ""
        dst_mac = ""
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst
            
        payload = bytes(tcp_layer.payload)
        
        # Scapy flags are essentially strings in older versions or FlagValues, we can use flags to extract boolean values
        flags = tcp_layer.flags
        
        return PacketRecord(
            timestamp=datetime.fromtimestamp(float(pkt.time)),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ip_version=ip_layer.version,
            ttl=ip_layer.ttl,
            protocol="TCP",
            src_port=tcp_layer.sport,
            dst_port=tcp_layer.dport,
            seq=tcp_layer.seq,
            ack=tcp_layer.ack,
            window_size=tcp_layer.window,
            flags=int(flags),
            is_syn='S' in flags,
            is_ack='A' in flags,
            is_fin='F' in flags,
            is_rst='R' in flags,
            is_psh='P' in flags,
            is_urg='U' in flags,
            payload_length=len(payload),
            payload=payload
        )
