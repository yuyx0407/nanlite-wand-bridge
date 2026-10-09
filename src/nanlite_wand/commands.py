#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""commands.py —— 南光 Wand 的「能力矩阵」与厂商命令构造

★ 驱动这盏灯真正生效的是 Feasycom 的 **8 字节快速命令**，配 opcode `C1 11 11`：

    [0] rollCode     防重放的递增计数（必须单调前进，固定值会被丢）
    [1] functionCode bit5=操作（1 SET / 0 QUERY），bit0=needReturn（1 要求回话）
    [2] typeCode     灯控恒为 0x01
    [3] optionCode   见下表
    [4:6] value      uint16 大端
    [6:8] channel    uint16 大端，单播填 0

能力矩阵（全部为肉眼/灯屏读数实测，不是推断）：

    option  含义      标尺（实测锚点）                        状态
    0x01    亮度      0–100 直值                              ✅ 生效
    0x03    色温      开尔文直值（2700/3300/5600 按值生效）    ✅ 生效
    0x04    绿/品     0–100，**50 = 中性**（断电重开也是 50）  ✅ 生效
    0x05    色相      tint 模式下 0–360                       ❌ 被解析、被 ACK，但光不变
    0x0C    饱和      tint 模式下 0–100                       ❌ 同上
    QUERY   读状态    func=0x01 + needReturn                  ⚠️ 只回一帧固定 ACK，不带状态

    ⇒ 彩色进不去：「模式」这一维不在快速命令 option 组里，只在 fullCmd 结构里，
      而这台灯**不吃 fullCmd**（opcode C0..CF 全扫过，0 回包 0 生效）。见 docs/PROTOCOL.md。
    ⇒ 状态回读只能靠"最后一次下发的命令值"，灯既不回应答值也不主动推。

⚠️ 别把那帧 ACK 当"参数有效"的判据：option 0x00..0x2F **全部**都会回同一帧 ACK。
   唯一判据是肉眼看到光变了。
"""

from __future__ import annotations

from typing import Optional

from .config import Config, data_file
from .stack import vendor_opcode

# ── option 码 ────────────────────────────────────────────────────────
OPT_DIM, OPT_CCT, OPT_GM, OPT_HUE, OPT_SAT = 0x01, 0x03, 0x04, 0x05, 0x0C
OPT_NAME = {OPT_DIM: "亮度", OPT_CCT: "色温", OPT_GM: "绿/品",
            OPT_HUE: "色相", OPT_SAT: "饱和"}

SET, QUERY = 0x20, 0x01
NEED_RETURN = 0x01
TYPE_LIGHT = 0x01

CID = 0x1111
CMD_FAST = 0x01          # → opcode C1 11 11：驱动光的那个命令码
CMD_STATUS = 0x02        # → opcode C2 11 11：状态/应答码，不是命令码

GM_NEUTRAL = 50          # 线上 50 = 用户 0
RANGE = {
    OPT_DIM: (0, 100),
    OPT_CCT: (2700, 6500),
    OPT_GM: (0, 100),
    OPT_HUE: (0, 360),
    OPT_SAT: (0, 100),
}
SUPPORTED = (OPT_DIM, OPT_CCT, OPT_GM)      # 实测能驱动光的三个


class Roll:
    """rollCode 持久计数器（防重放），落在配置数据目录里。"""

    FILE = "roll.txt"

    def __init__(self, name: str = FILE):
        self.path = data_file(name)

    def next(self, step: int = 1) -> int:
        try:
            v = int(self.path.read_text().strip())
        except Exception:
            v = 0x20
        v = (v + step) & 0xFF
        self.path.write_text(str(v))
        return v

    def peek(self) -> int:
        try:
            return int(self.path.read_text().strip())
        except Exception:
            return 0x20


_ROLL = Roll()


def set_roll(roll: int) -> None:
    """测试用：固定 rollCode，让字节输出可复现"""
    _ROLL.path.write_text(str(roll & 0xFF))


def fast_cmd(option: int, value: int = 0, func: int = SET,
             type_code: int = TYPE_LIGHT, channel: int = 0,
             roll: Optional[int] = None) -> bytes:
    """构造 8 字节快速命令载荷（不给 roll 就自增）"""
    r = _ROLL.next() if roll is None else (roll & 0xFF)
    return (bytes([r, func, type_code, option & 0xFF])
            + (value & 0xFFFF).to_bytes(2, "big")
            + (channel & 0xFFFF).to_bytes(2, "big"))


def clamp(option: int, value: int) -> int:
    lo, hi = RANGE.get(option, (0, 0xFFFF))
    return max(lo, min(hi, int(value)))


def command(option: int, value: int, want_reply: bool = False,
            roll: Optional[int] = None) -> bytes:
    """厂商 AccessPDU = opcode ‖ 载荷（实际下发就发这个）"""
    func = SET | (NEED_RETURN if want_reply else 0)
    return (vendor_opcode(CMD_FAST, CID)
            + fast_cmd(option, clamp(option, value), func, roll=roll))


def query(option: int, roll: Optional[int] = None) -> bytes:
    """QUERY + needReturn：实测只会拿到固定 ACK（留着做实验，别指望读状态）"""
    return (vendor_opcode(CMD_FAST, CID)
            + fast_cmd(option, 0, QUERY | NEED_RETURN, roll=roll))


def legacy_full_cct(dim_pct: int, cct: int = 5600, gm: float = 0) -> bytes:
    """别的机型（PavoTube / FC 系列）的 fullCmd 写法；**Wand 实测不驱动光**，
    只留作跨机型对照实验。"""
    gm_wire = int(round(gm + GM_NEUTRAL)) & 0xFF
    return (bytes([_ROLL.next(), 0x01]) + (dim_pct & 0xFF).to_bytes(2, "big")
            + bytes([0x02, 0x02]) + (cct & 0xFFFF).to_bytes(2, "big")
            + bytes([gm_wire, 0x00]))


class WandCommands:
    """在一条 WandSession 上发命令。硬件桥也复用这一层——它只依赖 session。"""

    def __init__(self, session, cfg: Optional[Config] = None):
        self.s = session
        self.cfg = cfg or session.cfg

    @property
    def dst(self) -> int:
        return self.cfg.get("node_addr")

    async def set(self, option: int, value: int, what: str = "",
                  drain: float = 0.0) -> None:
        pdu = command(option, value)
        await self.s.send_access(self.dst, pdu, akf=True,
                                 what=what or OPT_NAME.get(option, hex(option)),
                                 retry=self.cfg.get("retry"), gap=0.0)
        if drain:
            await self.s.drain(drain)

    async def brightness(self, pct: int) -> None:
        await self.set(OPT_DIM, pct, f"亮度{pct}%")

    async def cct(self, kelvin: int) -> None:
        await self.set(OPT_CCT, kelvin, f"色温{kelvin}K")

    async def green_magenta(self, wire: int) -> None:
        await self.set(OPT_GM, wire, f"绿/品{wire}")

    async def raw(self, access_pdu: bytes, what: str = "raw",
                  wait: float = 14.0) -> list:
        """注入任意厂商 AccessPDU（opcode 自带），等回包并返回解出的消息"""
        await self.s.send_access(self.dst, access_pdu, akf=True, what=what,
                                 retry=self.cfg.get("retry"), gap=0.0)
        return await self.s.drain(wait)
