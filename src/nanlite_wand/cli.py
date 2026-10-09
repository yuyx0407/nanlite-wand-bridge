#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cli.py —— 一条命令走完「找灯 → 配网 → 装钥匙 → 控灯 → 常驻」

    nanlite-wand selftest                     纯计算自检（不需要硬件）
    nanlite-wand scan                         找灯，打印地址与信标里的 NetworkID
    nanlite-wand provision                    PB-GATT 配网（**现生成随机密钥**并落盘）
    nanlite-wand bind                         装 AppKey + 绑厂商模型 + TTL 探针
    nanlite-wand set --brightness 40 [--cct 3200] [--gm 50]
    nanlite-wand raw c1:08ffff0301555564      注入任意厂商 AccessPDU（做实验用）
    nanlite-wand listen --seconds 30          只收不发：看灯会不会主动推状态
    nanlite-wand serve                        常驻 MQTT 桥（HomeKit 接这一条）

公共参数：`--config PATH`、`--address XX:XX:...`、`--target P24002`、`--node 0x0002`
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Optional

from . import commands as CMD
from . import crypto as MC
from . import net as NET
from . import stack as ST
from .auth import FeasyAuth
from .config import Config
from .link import BleProxyLink
from .stack import WandSession


def build_config(args: argparse.Namespace) -> Config:
    cfg = Config.load(getattr(args, "config", None))
    for key in ("ble_address", "target_name"):
        v = getattr(args, key, None)
        if v:
            cfg.set(key, v)
    if getattr(args, "node", None) is not None:
        cfg.set("node_addr", args.node)
    return cfg


async def open_session(cfg: Config, auth: bool = True) -> WandSession:
    """连上灯 → 必做 TEA 认证 → 用 $FSCCMD001$ 校正控制目标地址

    不认证也能让灯解开并回显厂商帧，但**光不会动** —— 这一步省不掉。
    """
    link = BleProxyLink(cfg.get("target_name"), cfg.get("ble_address"), log=print)
    await link.open()
    NET.configure(cfg)
    sess = WandSession(link, cfg)
    if not auth:
        return sess
    fa = FeasyAuth(link, rounds=cfg.get("tea_rounds"),
                   tea_key_hex=cfg.get("tea_key"))
    await fa.start()
    ok = await fa.authenticate()
    addr, iv = await fa.query_all()
    if not ok:
        print("⚠️ TEA 认证失败：灯会收到命令但不驱动光。"
              "给灯断电重插后再试；仍不行就是 TEA 密钥/轮数不对（见 docs/PROTOCOL.md）")
    if addr:
        cfg.set("node_addr", addr)
        print(f"  灯自报 Mesh 单播地址 = 0x{addr:04X}"
              f"{'' if iv is None else f'  IV Index = {iv}'}")
    return sess


async def cmd_selftest(_a) -> int:
    if not MC.self_test_quick():
        print("✗ Mesh 密码学自检失败")
        return 1
    from .auth import selftest_tea
    await selftest_tea()
    CMD.set_roll(0x40)
    print("\n  命令字节夹具（rollCode 固定 0x40，可复现）：")
    for opt, val in ((CMD.OPT_DIM, 40), (CMD.OPT_CCT, 3200), (CMD.OPT_GM, 50)):
        pdu = CMD.command(opt, val, roll=0x40)   # 固定 rollCode，字节输出可复现
        print(f"    {CMD.OPT_NAME[opt]:>4}={val:<6} → {pdu.hex()}  "
              f"opcode={pdu[:3].hex()} 载荷={pdu[3:].hex()}")
    print("\n✅ 自检通过")
    return 0


async def cmd_scan(a) -> int:
    cfg = build_config(a)
    link = BleProxyLink(cfg.get("target_name"), cfg.get("ble_address"), log=print)
    await link.open()
    print(f"  地址 = {link.address}")
    await link.close()
    return 0


async def cmd_provision(a) -> int:
    from .provision import main as provision_main
    await provision_main(list(filter(None, [a.args])))
    return 0


async def cmd_bind(a) -> int:
    from . import keysetup
    cfg = build_config(a)
    sess = await open_session(cfg)
    try:
        await keysetup.probe_alive(sess, cfg)
        rep = await keysetup.install_app_key(sess, cfg)
        print("  " + "  ".join(rep))
        if "Add=0x00" in " ".join(rep):
            print("  ✓ AppKey 已装到索引 0")
        else:
            print("  ⚠️ AppKey Add 状态码不是 0x00 —— 见 docs/TROUBLESHOOTING.md")
    finally:
        ST.save_seq(sess.node.seq)
        await sess.link.close()
    return 0


async def cmd_set(a) -> int:
    cfg = build_config(a)
    sess = await open_session(cfg)
    try:
        c = CMD.WandCommands(sess, cfg)
        if a.gm is not None:
            await c.green_magenta(a.gm)
        if a.cct is not None and a.brightness is None:
            await c.cct(a.cct)                      # 只发色温时先保持当前亮度不动
        if a.brightness is not None:
            await c.brightness(a.brightness)
            if a.cct is not None:
                await c.cct(a.cct)
        await asyncio.sleep(0.3)
        ST.save_seq(sess.node.seq)
    finally:
        await sess.link.close()
    print("  已下发（判据是肉眼看到光变了）")
    return 0


async def cmd_raw(a) -> int:
    cfg = build_config(a)
    sess = await open_session(cfg)
    try:
        body = a.frame.split(":", 1)
        hexstr = body[-1]
        pdu = bytes.fromhex(hexstr.replace(" ", ""))
        if len(body) == 1:
            pdu = ST.vendor_opcode(CMD.CMD_FAST) + pdu
        msgs = await CMD.WandCommands(sess, cfg).raw(pdu, what="raw")
        print(f"  回包 {len(msgs)} 条" if msgs else "  14 秒内无回包")
        ST.save_seq(sess.node.seq)
    finally:
        await sess.link.close()
    return 0


async def cmd_listen(a) -> int:
    """只收不发：验证「灯会不会主动推状态」（旋钮改了手机能不能知道）"""
    cfg = build_config(a)
    sess = await open_session(cfg, auth=False)
    print(f"  监听 {a.seconds}s，期间请在灯上转旋钮……")
    try:
        loop, stop = asyncio.get_event_loop(), asyncio.Event()
        end = loop.time() + a.seconds
        n = 0
        while loop.time() < end:
            await asyncio.sleep(1.0)
            for m in sess.sweep():
                n += 1
                print(f"  ← opcode=0x{m['opcode']:04X} akf={m['akf']} "
                      f"参数={m['params'].hex()}")
        print(f"  共收到 {n} 条来帧" + ("" if n else "  ⇒ 这盏灯不会主动推状态"))
    finally:
        await sess.link.close()
    return 0


async def cmd_serve(a) -> int:
    from .bridge import amain
    await amain()
    return 0


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="nanlite-wand",
                                 description="控制走蓝牙 SIG Mesh 的南光灯（Nanlite Wand 等）")
    ap.add_argument("--config", help="配置文件（默认 ~/.config/nanlite-wand/config.json）")
    ap.add_argument("--address", dest="ble_address", help="跳过扫描，直接给 BD_ADDR / CoreBluetooth UUID")
    ap.add_argument("--target", dest="target_name", help="广播名前缀（默认 P24002）")
    ap.add_argument("--node", type=lambda x: int(x, 0), help="灯的 Mesh 单播地址，如 0x0002")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("selftest", help="纯计算自检，不需要硬件")
    sub.add_parser("scan", help="找灯")

    p = sub.add_parser("provision", help="PB-GATT 配网")
    p.add_argument("args", nargs="*", help="透传给配网器（如 --sweep）")

    sub.add_parser("bind", help="装 AppKey + 绑厂商模型")

    p = sub.add_parser("set", help="下发参数")
    p.add_argument("--brightness", type=int, help="0-100")
    p.add_argument("--cct", type=int, help="色温开尔文，2700-6500")
    p.add_argument("--gm", type=int, help="绿/品 0-100，50=中性")

    p = sub.add_parser("raw", help="注入厂商 AccessPDU（实验用）")
    p.add_argument("frame", help="如 c1:08ffff0301555564 或整帧 hex")

    p = sub.add_parser("listen", help="只收不发，看灯会不会主动推")
    p.add_argument("--seconds", type=float, default=30.0)

    sub.add_parser("serve", help="常驻 MQTT 桥")
    return ap


HANDLERS = {"selftest": cmd_selftest, "scan": cmd_scan, "provision": cmd_provision,
            "bind": cmd_bind, "set": cmd_set, "raw": cmd_raw,
            "listen": cmd_listen, "serve": cmd_serve}


def main(argv: Optional[list] = None) -> int:
    args = parser().parse_args(argv)
    try:
        return asyncio.run(HANDLERS[args.cmd](args))
    except KeyboardInterrupt:
        return 130
    except ConnectionError as e:
        print(f"✗ {e}")
        print("  检查：灯有没有通电、有没有被手机 App 占着（灯的 BLE 只接受一条连接）、"
              "macOS 上是否给了蓝牙权限")
        return 1


if __name__ == "__main__":
    sys.exit(main())
