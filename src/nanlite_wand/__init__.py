#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nanlite_wand —— 把走蓝牙 SIG Mesh（Feasycom FeasyMesh）的南光灯接进任何控制器

分层（硬件桥只需替换最底下一层）：

    config.py     所有「换个人就得改」的值
    link.py       MeshLink 接口 + BleProxyLink（BLE GATT Proxy / 0xFFF0 厂商通道）
    stack.py      Mesh 网络层/传输层编解码 + 会话（与传输无关）
    crypto.py     Mesh 密钥推导与 AES-CCM/CMAC（含自检）
    net.py        帧构造/解析、Config opcode
    auth.py       Feasycom TEA 认证（每次连接必做）
    commands.py   快速命令 + 能力矩阵（哪些参数真能驱动光）
    keysetup.py   配网后的 AppKey 安装与厂商模型绑定
    provision.py  PB-GATT 配网
    bridge.py     MQTT ↔ 灯 的常驻服务（HomeKit 侧接这里）
"""

from .config import Config, data_dir, data_file
from .link import BleProxyLink, MeshLink
from .stack import WandSession
from .auth import FeasyAuth
from . import commands, crypto, net

__all__ = ["Config", "data_dir", "data_file", "BleProxyLink", "MeshLink",
           "WandSession", "FeasyAuth", "commands", "crypto", "net"]
__version__ = "0.1.0"
