#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""setup.py —— 配网之后、控灯之前的「装钥匙」三步（Config 层，有回执可验）

刚配完网的灯只认网络层，厂商命令解不开，必须先做完：

    1. Config AppKey Add      0x8000   把我们的 AppKey 写到索引 0        ← 有 AppKey Status 回执
    2. Config Model App Bind  0x803D   把索引 0 绑到厂商模型 0x11111111   ← 有 Model App Status 回执
    3.（复查）Config AppKey Get 0x8001

两个坑（都踩过，别再来一遍）：
  · **AppKey Add 的 opcode 是单字节 0x0000**，Delete 才是 0x8000 —— 各家资料经常写反；
    发错的话灯会回一个非 0 的状态码，看着像"成功失败"，其实是 opcode 用错。
  · Model App Bind 的参数是**小端**打包的（从库字节码
    `ConfigModelAppBind.assembleMessageParameters` 读出）：
        元素地址(LE) ‖ AppKeyIndex(2B，两字节顺序调换过的) ‖ CID(LE) ‖ ModelID(LE)
"""

from __future__ import annotations

from typing import Optional

from . import net as MN
from . import stack as ST
from .config import Config


async def config_message(session, dst: int, opcode: int, params: bytes,
                         what: str, wait: float = 10.0, log=print) -> list[dict]:
    """发一条 Config 消息（DeviceKey 通道，AKF=0）并收回执"""
    await session.send_access(dst, MN.encode_opcode(opcode) + params,
                              akf=False, what=what, retry=2, gap=1.2)
    msgs = await session.drain(wait)
    for m in msgs:
        if m.get("opcode") is not None:
            log(f"  ← {what} 回包 opcode=0x{m['opcode']:04X} 参数={m['params'].hex()}")
    return msgs


def _status(msgs: list[dict], want: int) -> Optional[int]:
    for m in msgs:
        if m.get("opcode") == want and m.get("params"):
            return m["params"][0]
    return None


async def install_app_key(session, cfg: Optional[Config] = None,
                          log=print) -> list[str]:
    """装 AppKey 到索引 0 并绑到厂商模型；返回每步的状态摘要"""
    cfg = cfg or session.cfg
    dst = cfg.get("node_addr")
    idx = cfg.get("key_index")
    report: list[str] = []

    msgs = await config_message(session, dst, ST.OP_APPKEY_ADD,
                                ST.pack_key_indexes(idx, idx),
                                "AppKey Delete idx0", 12.0, log)
    st = _status(msgs, ST.OP_APPKEY_STATUS)
    report.append(f"Delete={'0x%02X' % st if st is not None else '无回包'}")

    msgs = await config_message(session, dst, 0x0000,
                                ST.pack_key_indexes(idx, idx) + session.node.app_key,
                                "AppKey Add idx0", 14.0, log)
    st = _status(msgs, ST.OP_APPKEY_STATUS)
    report.append(f"Add={'0x%02X' % st if st is not None else '无回包'}")

    for bind_idx in (idx, 1):
        params = (dst.to_bytes(2, "little") + bind_idx.to_bytes(2, "big")
                  + ST.VENDOR_CID.to_bytes(2, "little")
                  + ST.VENDOR_MODEL.to_bytes(2, "little"))
        msgs = await config_message(session, dst, ST.OP_MODEL_BIND, params,
                                    f"Model App Bind idx{bind_idx}", 12.0, log)
        st = _status(msgs, ST.OP_MODEL_STATUS)
        report.append(f"Bind{bind_idx}={'0x%02X' % st if st is not None else '无回包'}")

    msgs = await config_message(session, dst, 0x8001, b"\x00\x00",
                                "AppKey Get", 10.0, log)
    for m in msgs:
        if m.get("opcode") == 0x8002:
            report.append(f"索引列表={m['params'].hex()}")
    return report


async def probe_alive(session, cfg: Optional[Config] = None, log=print) -> bool:
    """TTL Get 探针：有回执就说明 Mesh + DeviceKey 通道是通的（与"灯会不会动光"无关）"""
    cfg = cfg or session.cfg
    msgs = await config_message(session, cfg.get("node_addr"), ST.OP_TTL_GET,
                                b"", "Default TTL Get", 8.0, log)
    st = _status(msgs, ST.OP_TTL_STATUS)
    if st is None:
        log("  ✗ 8 秒内灯无回执 —— Mesh 层就不通（重连/重配网）")
        return False
    log(f"  ✓ 灯在听（TTL={st:02X}）")
    return True
