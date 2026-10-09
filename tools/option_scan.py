#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""option_scan.py —— 用 ACK 当尺子，扫出这台灯到底认哪些 option 码

为什么能这么做（2026-10-07 22:47 实测）：
  · 快速命令 carrier（C1 11 11 + 8B）只要灯认，就会回一帧固定 ACK `01 22 02 01 0000 0000`
    —— 设亮度 35 和设 60 回的**一模一样**，所以它是"认下这帧"的 ACK，不带状态值。
  · 彩色 fullCmd 用 C0..CF 全扫过：0 条 ACK ⇒ fullCmd 这条在这台灯上不成立（连同 opcode 一起排除）。
  ⇒ 于是"有没有 ACK"就是接受/拒绝的自动判据，不需要人盯灯。

扫的是什么：vmedea 原表说 option 0x05 是 **tint 模式下的色相**，模式位不在快速命令这组里。
如果 0x05/0x0C 有 ACK 却不生效，说明"进不去模式"；如果另外某个 option 也有 ACK，
那它就是"模式/开关"这一维的候选，拿它配合 0x05/0x0C 再试一次就有戏。

跑法：
    python3 tools/option_scan.py
    # macOS 需要蓝牙权限（见 deploy/install-macos.sh）。跑之前先挂维护锁让常驻桥别碰蓝牙：
    #   touch "${NANLITE_DATA_DIR:-$HOME/.local/share/nanlite-wand}/maintenance.lock"
    # 跑完删锁并重启桥 —— 灯只有一条 BLE 连接。
    # ⚠️ 本脚本会把非中性值写进灯的寄存器，跑完必须执行 tools/tint_reset.py 复位。

"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nanlite_wand import commands as CMD
from nanlite_wand import stack as ST
from nanlite_wand.cli import open_session
from nanlite_wand.config import Config

VALUE = 0x0078          # 对大多数参数都是"明显偏离默认"的值（120）
OPTS = list(range(0x00, 0x30))


async def probe(w, dst, option, wait=2.0):
    """func=0x21 = SET|needReturn：既要生效也要回话；单发不重发，省时间。"""
    pdu = CMD.opcode(0x01) + CMD.fast_cmd(option, VALUE, func=0x21)
    await w.send_access(dst, pdu, akf=True, what=f"option 0x{option:02X}",
                        retry=1, gap=0.0)
    return len([m for m in await w.drain(wait) if m.get("opcode") is not None])


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

    ST.hr("判据自检：option 0x01（亮度，已知生效）必须有 ACK")
    ctl = await probe(w, dst, CMD.OPT_DIM)
    print(f"  自检 ACK={ctl} 条 →{'判据可用' if ctl else '判据不可用，整轮作废'}", flush=True)

    ST.hr(f"主扫：option 0x00..0x2F（func=0x21，值={VALUE}）")
    acks = {}
    for o in OPTS:
        acks[o] = await probe(w, dst, o)
        if acks[o]:
            print(f"     ★ option 0x{o:02X} 有 ACK（{acks[o]} 条）", flush=True)

    ST.hr("收尾：把灯拉回亮度 50%，别留在怪状态")
    await probe(w, dst, CMD.OPT_DIM, wait=1.0)
    pdu = CMD.opcode(0x01) + CMD.fast_cmd(CMD.OPT_DIM, 50, func=0x21)
    await w.send_access(dst, pdu, akf=True, what="DIM=50 复位", retry=1, gap=0.0)
    await w.drain(1.0)

    ST.hr("结论")
    known = {0x01: "亮度", 0x03: "色温", 0x04: "绿/品", 0x05: "色相(tint)", 0x0C: "饱和"}
    got = [f"0x{o:02X}({known.get(o, '?')})" for o, n in acks.items() if n]
    print(f"  有 ACK 的 option：{got or '（只有自检那条，说明 ACK 判据在这轮里没区分度）'}", flush=True)
    print(f"  无 ACK 的数量：{sum(1 for n in acks.values() if not n)} / {len(OPTS)}", flush=True)
    print("  读法：0x05/0x0C 有 ACK 但灯不变 → 卡的是模式，不是码；"
          "\n        冒出别的有 ACK 的 option → 它就是『模式/开关』候选，下一轮拿它配 0x05/0x0C。", flush=True)
    ST.save_seq(w.node.seq)
    await w.client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
