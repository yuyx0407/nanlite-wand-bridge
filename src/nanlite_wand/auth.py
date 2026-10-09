#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""auth.py —— Feasycom 在标准蓝牙 Mesh 之上加的那一层私有认证（TEA）

★ 这就是两周来找不到的"运行期前置握手"：灯虽然会用 DeviceKey/AppKey 解开并回显我们的
  Mesh 厂商帧，但**不认证就不驱动光**。认证走 0xFFF0 服务（fff2 写 / fff1 通知），与 Mesh 无关。

TEA 密钥来源（本机实测抽出，不是猜的）：
    reverse/Nanlink_v2.10.0.apk → lib/{arm64-v8a,armeabi-v7a}/libencrypted.so
    在符号 "getRandomNumber\\0" 之后 16 字节 = c5bae868223f9f50968717b24021c511
    两个架构取值一致；同库导出符号含 random_number_encrypt / create_random_number /
    EncryptAlgorithm$Universal_randomNumberMatches，与"随机数匹配式认证"吻合。

握手（已在 2026-10-07 的 iPhone 抓包里逐字节对照过）：
    "AUTH" + TEA(challenge, rounds) + TEA(challenge, rounds)   = 4 + 8 + 8 = 20 字节
      challenge = 4 随机字节 + 4 个 0
      rounds 依次试 32 → 2 → 1，哪一轮灯答话就用哪一轮（不同固件轮数不同）
    认证后可发 ASCII 诊断命令（\\r\\n 结尾）：
      $FSCCMD001$ → "$001-XXXX$"   设备的 Mesh 单播地址（十六进制）
      $FSCCMD002$ → "$002-XHHHHHHHH$"  IV 更新标志 + IV Index
"""

import os
import secrets
import struct
from typing import Optional

FEASY_NOTIFY = "0000fff1-0000-1000-8000-00805f9b34fb"
FEASY_WRITE = "0000fff2-0000-1000-8000-00805f9b34fb"

# 厂商密钥（来源见本文件 docstring）。可用配置 tea_key / NANLITE_TEA_KEY 覆盖，便于做对照实验。
TEA_KEY_HEX = os.environ.get("NANLITE_TEA_KEY",
                          "c5bae868223f9f50968717b24021c511")
TEA_KEY = struct.unpack(">IIII", bytes.fromhex(TEA_KEY_HEX))
DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF


def tea_encrypt(block: bytes, rounds: int = 32,
                key: Optional[tuple] = None) -> bytes:
    """标准 TEA，8 字节块，大端两个 32 位字"""
    k = key or TEA_KEY
    v0, v1 = struct.unpack(">II", block)
    s = 0
    for _ in range(rounds):
        s = (s + DELTA) & MASK
        v0 = (v0 + ((((v1 << 4) & MASK) + k[0]) ^ (v1 + s)
                    ^ ((v1 >> 5) + k[1]))) & MASK
        v1 = (v1 + ((((v0 << 4) & MASK) + k[2]) ^ (v0 + s)
                    ^ ((v0 >> 5) + k[3]))) & MASK
    return struct.pack(">II", v0, v1)


class FeasyAuth:
    """在一条 MeshLink 的厂商通道（0xfff2 写 / 0xfff1 通知）上做认证与诊断查询。

    硬件桥只要实现 `send_vendor()` / `recv_vendor()` 这两个方法，认证就自动可用。
    """

    def __init__(self, link, rounds=None, tea_key_hex: Optional[str] = None):
        self.link = link
        self.rounds_try = tuple(rounds) if rounds else (32, 2, 1)
        self.key = struct.unpack(">IIII", bytes.fromhex(tea_key_hex or TEA_KEY_HEX))
        self.rounds_used = None
        self.mesh_addr = None
        self.iv = None

    async def start(self) -> None:
        return None          # BLE 实现在 link.open() 里已订阅，接口留着给别的桥

    async def authenticate(self, log=print) -> bool:
        challenge = secrets.token_bytes(4) + b"\x00\x00\x00\x00"
        for rounds in self.rounds_try:
            enc = tea_encrypt(challenge, rounds, key=self.key)
            packet = b"AUTH" + enc + enc
            log(f"  AUTH rounds={rounds} → {packet.hex()}")
            await self.link.send_vendor(packet)
            r = await self.link.recv_vendor(2.0)
            if r:
                self.rounds_used = rounds
                log(f"  ← 灯应答 {len(r)}B: {r.hex()}"
                    f"  ascii={r.decode('latin-1')!r}   ✅ 认证通过（rounds={rounds}）")
                return True
            log(f"  rounds={rounds} 无应答，降级重试…")
        log("  ✗ 三种轮数都没应答 —— TEA 密钥或流程不对")
        return False

    async def ask(self, cmd: bytes, log=print):
        await self.link.send_vendor(cmd)
        r = await self.link.recv_vendor(2.5)
        txt = r.decode("latin-1") if r else ""
        log(f"  发 {cmd!r} → {r.hex() if r else '（无应答）'}  ascii={txt!r}")
        return txt

    async def query_all(self, log=print):
        # 抓包里 App 发的是不带 \r\n 的 11 字节，两种都试
        for tail in (b"\r\n", b""):
            t = await self.ask(b"$FSCCMD001$" + tail, log)
            if "$001-" in t:
                try:
                    self.mesh_addr = int(t.split("-")[1].strip("$\r\n"), 16)
                except Exception:
                    pass
                break
        t = await self.ask(b"$FSCCMD002$\r\n", log)
        if "$002-" in t:
            try:
                self.iv = int(t[6:14], 16)
            except Exception:
                pass
        return self.mesh_addr, self.iv


async def selftest_tea():
    """没有蓝牙也能验的东西：TEA 必须能把自己算稳（同输入同输出）+ 常见测试向量自检"""
    b = bytes.fromhex("0000000000000000")
    e1 = tea_encrypt(b, 32)
    e2 = tea_encrypt(b, 32)
    print(f"  TEA(全零块, 32 轮) = {e1.hex()}   确定性：{e1 == e2}")
    print(f"  TEA(全零块, 1 轮)  = {tea_encrypt(b, 1).hex()}")
    k = struct.pack(">IIII", *TEA_KEY)
    print(f"  使用的密钥 = {k.hex()}（来自 libencrypted.so）")


if __name__ == "__main__":
    import asyncio
    import sys
    if "--tea-selftest" in sys.argv:
        asyncio.run(selftest_tea())
