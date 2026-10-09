#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""字节级回归：命令与 opcode 必须是确定的（硬件不在场也能验最有价值的一层）"""
import os
import sys

os.environ["NANLITE_DATA_DIR"] = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", ".test-data"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nanlite_wand import commands as CMD      # noqa: E402
from nanlite_wand import net as NET           # noqa: E402
from nanlite_wand import stack as ST          # noqa: E402
from nanlite_wand import crypto as MC        # noqa: E402
from nanlite_wand.config import Config        # noqa: E402


def check(name, got, want):
    assert got == want, f"{name}: got {got} want {want}"
    print(f"  ✓ {name}")


def test_commands():
    CMD.set_roll(0x40)
    check("厂商 opcode C1", ST.vendor_opcode(CMD.CMD_FAST).hex(), "c11111")
    check("亮度 40%", CMD.command(CMD.OPT_DIM, 40, roll=0x40).hex(),
          "c1111140200101002800 00".replace(" ", ""))
    check("色温 3200K", CMD.command(CMD.OPT_CCT, 3200, roll=0x40).hex(),
          "c11111402001030c800000")
    check("绿/品 50（中性）", CMD.command(CMD.OPT_GM, 50, roll=0x40).hex(),
          "c111114020010400320000")
    check("QUERY 亮度", CMD.query(CMD.OPT_DIM, roll=0x40).hex(),
          "c11111400101010000 0000".replace(" ", ""))
    check("超范围被夹住", CMD.clamp(CMD.OPT_DIM, 500), 100)


def test_mesh_keys():
    # RFC 4493 CMAC 标准向量 + AES-CCM 往返（规范级正确性，不靠我们自己造常数）
    assert MC.self_test_quick(), "mesh 密码学自检未通过"
    print("  ✓ crypto 自检（RFC 4493 CMAC 向量 + CCM 往返）")
    nk = bytes.fromhex("3DE586F071B86D431B4931776AF22D08")
    a = NET.k2_library(nk)
    b = NET.k2_library(nk)
    check("k2 确定性（NID/EncryptionKey/PrivacyKey 三次一致）", a == b, True)
    check("k3 确定性", NET.k3(nk) == NET.k3(nk), True)
    check("k4 是 6 位 AID", NET.k4(nk) & ~0x3F, 0)


def test_frame_roundtrip():
    cfg = Config.load()
    cfg.set("net_key", "3DE586F071B86D431B4931776AF22D08")
    cfg.set("app_key", "2DC110BB1BA9C92321B15F1D1F39B036")
    cfg.set("dev_key", "00112233445566778899AABBCCDDEEFF")
    NET.configure(cfg)
    node = NET.MeshNode(net_key=bytes.fromhex(cfg.get("net_key")),
                        app_key=bytes.fromhex(cfg.get("app_key")),
                        dev_key=bytes.fromhex(cfg.get("dev_key")),
                        src=0x0001, seq=0x000001)
    access = ST.vendor_opcode(CMD.CMD_FAST) + CMD.fast_cmd(CMD.OPT_DIM, 40, roll=0x40)
    frame = node.build(0x0002, access, akf=True, seq=0x000001)
    check("整帧字节数（30B，与 App 抓包里的控制帧同形）", len(frame), 30)
    got = node.parse(frame)
    assert got, "自己构造的帧应能用同一把 NetKey 解开（网络层自证）"
    assert got.get("transport"), "解出来的传输层不应为空"
    print(f"  ✓ 网络层自解自造帧：keys={sorted(got)} "
          f"SRC=0x{got['src']:04X} transport={got['transport'].hex()}")


if __name__ == "__main__":
    import shutil
    for fn in (test_commands, test_mesh_keys, test_frame_roundtrip):
        print(f"\n== {fn.__name__}")
        fn()
    shutil.rmtree(os.environ["NANLITE_DATA_DIR"], ignore_errors=True)
    print("\n✅ 全部字节回归通过")
