#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mdns_check.py —— 读一份 tcpdump 抓的 5353 包，回答三个问题

    1) 手机有没有发出对 _hap._tcp 的查询？（除桥自身地址外的来源 = 客户端）
    2) Mac 有没有应答？应答里带的地址记录是哪个 IP？
    3) 有没有随后打向 51826 的 TCP？（这条 pcap 只抓 5353 时看不到，属正常）

判读：
  · 只看到手机在问、看不到我们答 ⇒ 广播没发到客户端（软 AP/组播问题），改广告方式或换网卡
  · 我们答了、手机还在反复问 ⇒ 应答内容手机不认（多半是地址/接口/IPv6 或缓存）
  · 手机根本没问 ⇒ 手机侧问题（本地网络权限 / 没连上这个 WLAN / Home App 缓存）

用法：  python3 mdns_check.py <pcap> --phone <客户端网段前缀> --mac <跑桥机器的地址>
抓包： sudo tcpdump -i <你的接口> -nn -w /tmp/mdns.pcap port 5353
"""

import argparse
import collections
import socket
import struct
import sys


def labels(data, off, seen=None):
    """把 DNS 名字（含压缩指针）读成字符串，返回 (name, 新偏移)"""
    seen = seen or set()
    parts, jumped, orig = [], False, off
    while True:
        if off >= len(data):
            break
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 2 > len(data):
                break
            ptr = int.from_bytes(data[off + 1:off + 3], "big") & 0x3FFF
            if ptr in seen:
                break
            seen.add(ptr)
            sub, _ = labels(data, ptr, seen)
            if sub:
                parts.append(sub)
            if not jumped:
                off += 2
                jumped = True
            break
        off += 1
        parts.append(data[off:off + n].decode("latin-1"))
        off += n
    return ".".join(p for p in parts if p), (orig if jumped else off)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--phone", required=True, help="客户端所在网段前缀（你自己填，如 10.0.0）")
    ap.add_argument("--mac", required=True, help="跑桥那台机器的地址（通告应答的来源）")
    args = ap.parse_args()

    buf = open(args.pcap, "rb").read()
    if len(buf) < 24:
        sys.exit("文件太小，不像 pcap")
    magic = buf[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    linktype = struct.unpack(endian + "I", buf[20:24])[0]
    off, n = 24, 0
    q_hap = collections.Counter()
    r_hap = collections.Counter()
    names_seen = collections.Counter()
    our_answers = 0
    total = 0

    while off + 16 <= len(buf):
        ts_s, ts_us, incl, orig = struct.unpack(endian + "IIII", buf[off:off + 16])
        off += 16
        pkt = buf[off:off + incl]
        off += incl
        total += 1
        if linktype == 1:                      # DLT_EN10MB
            eth_type = int.from_bytes(pkt[12:14], "big")
            ip_off = 14
        elif linktype == 12:                   # DLT_RAW
            ip_off = 0
            eth_type = 0x800
        else:
            continue
        if eth_type == 0x8100:
            eth_type = int.from_bytes(pkt[ip_off + 2:ip_off + 4], "big")
            ip_off += 4
        if eth_type not in (0x800, 0x86DD):
            continue
        if eth_type == 0x800:
            ihl = (pkt[ip_off] & 0x0F) * 4
            src = socket.inet_ntoa(pkt[ip_off + 12:ip_off + 16])
            proto = pkt[ip_off + 9]
            l4 = ip_off + ihl
        else:
            src = socket.inet_ntop(AF_INET6, pkt[ip_off + 8:ip_off + 24])
            proto = pkt[ip_off + 6]
            l4 = ip_off + 40
        if proto != 17:
            continue
        sport, dport, ulen = struct.unpack(">HHH", pkt[l4:l4 + 6])
        if 5353 not in (sport, dport):
            continue
        dns = pkt[l4 + 8:l4 + 6 + ulen]
        if len(dns) < 12:
            continue
        flags = int.from_bytes(dns[2:4], "big")
        qd, an = int.from_bytes(dns[4:6], "big"), int.from_bytes(dns[6:8], "big")
        p = 12
        for _ in range(qd):
            name, p = labels(dns, p)
            names_seen[name.lower()] += 1
            if "_hap" in name.lower():
                (r_hap if (flags & 0x8000) else q_hap)[src] += 1
            p += 4
        for _ in range(an):
            name, p = labels(dns, p)
            if len(dns) < p + 10:
                break
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", dns[p:p + 10])
            p += 10
            rdata = dns[p:p + rdlen]
            if name.lower().startswith("nanlite") or "_hap" in name.lower():
                names_seen[name.lower()] += 1
                if rtype == 1:
                    our_answers += 1
                    names_seen["A→" + socket.inet_ntoa(rdata)] += 1
            p += rdlen

    print(f"包总数 {total}")
    print(f"\n① 谁在查询 _hap._tcp（计数按源 IP）：")
    for k, v in q_hap.most_common(8):
        tag = "  ← 手机" if k.startswith(args.phone) and k != args.mac else ""
        print(f"   {k:<16} ×{v}{tag}")
    if not q_hap:
        print("   （没有任何 _hap 查询 ⇒ 手机根本没发问：查本地网络权限/是否真连上这个 WLAN）")
    print(f"\n② 谁在应答 _hap._tcp：")
    for k, v in r_hap.most_common(8):
        tag = "  ← 我们的桥" if k.startswith(args.mac) else ""
        print(f"   {k:<16} ×{v}{tag}")
    print(f"\n③ 出现过的名字/地址（含应答里的 A 记录）：")
    for k, v in names_seen.most_common(12):
        print(f"   ×{v:<4} {k}")
    print(f"\n④ 桥发出的 A 记录应答数：{our_answers}")


AF_INET6 = 30

if __name__ == "__main__":
    main()
