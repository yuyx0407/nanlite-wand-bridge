#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""opcode_scan.py —— 彩色为什么进不去：扫厂商 opcode，判据不用人眼

已确立的事实（2026-10-07 22:35）：
  · 快速命令 8B `[roll,func,type,option,val_be16,ch_be16]` 走 C1 11 11 **能驱动灯**（亮度/色温肉眼确认）
  · fullCmd（带模式字节 FLM 的那种）用 C1 和 C2 发出去：0 回包、灯不动 ⇒ 整条不认
  · vmedea 原表确认：option 0x05 是 **tint(彩色)模式下的**色相，0x0C 是饱和；
    而"模式"这一维不在快速命令的 option 组里，只在扩展/fullCmd 结构里
  · APK 里只有 $FSCCMD001$/002$，没有读参数的第三条明文通道
⇒ 剩下的唯一变量就是 opcode。C1/C2 只是我们试出来的两个，厂商 opcode 空间是 0xC0–0xFF。

判据（不靠眼睛）：QUERY 那轮证明**灯会回应答**，所以"有没有回包"能当接受/拒绝的粗判据。
为了让这条判据本身可信，前后各放一条已知能驱动灯的快速命令做阳性对照
（func=0x21 = SET|needReturn，既要生效也要回话）。

跑法：
    python3 tools/opcode_scan.py.py             # Linux 直接跑（BlueZ）
    # macOS：碰蓝牙的进程必须有 NSBluetoothAlwaysUsageDescription，
    # 用 ./deploy/install-macos.sh 生成的 .app 身份跑，或给终端授予蓝牙权限后直接跑

⚠️ 灯的 BLE 只接受一条连接：跑探针之前先让常驻桥别碰蓝牙 ——
    touch "$NANLITE_DATA_DIR/maintenance.lock"（桥会主动断开并保持不连），
    跑完再删掉锁并重启桥。SEQ/rollCode 是全局状态，探针与桥必须共用同一份数据目录。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nanlite_wand import commands as CMD
from nanlite_wand import stack as ST
from nanlite_wand.cli import open_session
from nanlite_wand.config import Config

HSI_FULL = bytes.fromhex("08ffff0301555564")     # SEQUENCE=8 DIM=100% FLM=03 SLM=01 HUE=120° SAT=100
LOWS = list(range(0x00, 0x10))                    # C0..CF


async def probe(w, dst, what, op_low, payload, wait=3.0):
    real = await CMD.send(w, dst, CMD.opcode(op_low), payload, True, what, wait=wait)
    return len(real)


async def main():
    cfg = Config.load()
    w = await open_session(cfg)          # 连接 + TEA 认证 + 地址校正
    fa = FeasyAuth(w.client)
    await fa.start()
    authed = await fa.authenticate()
    dst = ST.NODE_ADDR
    if authed:
        addr, _iv = await fa.query_all()
        if addr is not None:
            dst = addr
    print(f"\n  认证={'OK' if authed else '失败'}  目标=0x{dst:04X}", flush=True)
    ST.hr("阳性对照 A：快速命令 SET|needReturn 亮度=35（这条必须又亮又回话）")
    n_a = await probe(w, dst, "对照A 快速 DIM=35", 0x01,
                      CMD.fast_cmd(CMD.OPT_DIM, 35, func=0x21))

    ST.hr("主扫：opcode C0..CF × 彩色 fullCmd（100% 色相120° 饱和100）")
    hits = {}
    for low in LOWS:
        hits[low] = await probe(w, dst, f"fullCmd × opcode C{low:X}", low, HSI_FULL, wait=2.5)

    ST.hr("阳性对照 B：快速命令 SET|needReturn 亮度=60（证明链路到这儿还活着）")
    n_b = await probe(w, dst, "对照B 快速 DIM=60", 0x01,
                      CMD.fast_cmd(CMD.OPT_DIM, 60, func=0x21))

    ST.hr("结论")
    print(f"  对照 A 回包 {n_a} 条 / 对照 B 回包 {n_b} 条"
          f"  → 判据{'可用' if (n_a or n_b) else '不可用（连对照都不回话，这次整轮作废）'}", flush=True)
    got = {f"C{low:X}": n for low, n in hits.items() if n}
    print(f"  fullCmd 拿到回包的 opcode：{got or '一个都没有（C0..CF 全沉默）'}", flush=True)
    print("  若全沉默 → fullCmd 这条路在这台灯上彻底出局，彩色只能等别的入口；"
          "\n  若某个 Cxx 有回包 → 那才是扩展命令的命令码，接着拿它复核灯有没有真的变绿。", flush=True)
    ST.save_seq(w.node.seq)
    await w.client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
