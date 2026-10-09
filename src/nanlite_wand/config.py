#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""config.py —— 所有「换一个人就得改」的值都只在这里读一次

优先级：命令行显式参数 > 环境变量 > JSON 配置文件 > 内置默认。

配置文件查找顺序（找到第一个就用）：
    1. 环境变量 NANLITE_CONFIG 指向的路径
    2. ~/.config/nanlite-wand/config.json
    3. ./nanlite-wand.json

数据目录（SEQ / rollCode / DeviceKey / 状态缓存这些**必须持久化**的东西）：
    环境变量 NANLITE_DATA_DIR，默认 ~/.local/share/nanlite-wand
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

ENV_PREFIX = "NANLITE_"

# 内置默认：一台**全新、由本工具自己配网**的灯的初始假设。
# 密钥是随机的（provision 时现生成并写进数据目录），不预置任何私人网络参数。
DEFAULTS: dict[str, Any] = {
    # 目标设备
    "target_name": "P24002",          # 灯广播的名字（Nanlite Wand = P24002）
    "ble_address": None,              # 可选：写死 BD_ADDR / CoreBluetooth UUID，跳过扫描
    "vendor_cid": 0x1111,             # 厂商 Company ID
    "vendor_model": 0x1111,           # 厂商 Model ID
    # Mesh 网络（留空 = 由 provision 生成并落盘）
    "net_key": None,
    "app_key": None,
    "dev_key": None,
    "key_index": 0x0000,
    "iv_index": 0x00000000,
    "provisioner_addr": 0x0001,
    "node_addr": 0x0002,              # 会被 $FSCCMD001$ 的实际值校正
    "seq_start": 0x1000,
    # Feasycom 私有认证（厂商密钥，见 auth.py 的来源说明；可用 env 覆盖以做对比实验）
    "tea_key": "c5bae868223f9f50968717b24021c511",
    "tea_rounds": [32, 2, 1],
    # 常驻桥的接入方式
    "mqtt_host": "127.0.0.1",
    "mqtt_port": 1883,
    "mqtt_user": None,
    "mqtt_password": None,
    "topic_prefix": "nanlite/wand",
    "status_host": "127.0.0.1",       # 默认只听本机；要给别人访问自己显式改
    "status_port": 0,                 # 0 = 不起状态页
    # 时序（体感延迟主要在这里）
    "debounce_s": 0.10,
    "resend_gap_s": 0.10,
    "send_pace_s": 0.06,
    "retry": 1,
    "off_dim": 0,
    "sync_on_start": False,
}


def data_dir(create: bool = True) -> Path:
    p = Path(os.environ.get(ENV_PREFIX + "DATA_DIR",
                            "~/.local/share/nanlite-wand")).expanduser()
    if create:
        p.mkdir(parents=True, exist_ok=True)
    return p


def _config_path() -> Optional[Path]:
    for cand in (os.environ.get(ENV_PREFIX + "CONFIG"),
                 "~/.config/nanlite-wand/config.json",
                 "./nanlite-wand.json"):
        if not cand:
            continue
        p = Path(cand).expanduser()
        if p.is_file():
            return p
    return None


# 环境变量表：NANLITE_MQTT_HOST、NANLITE_DEBOUNCE_S …… 名字 = DEFAULTS 的键大写
def _from_env() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, default in DEFAULTS.items():
        raw = os.environ.get(ENV_PREFIX + key.upper())
        if raw is None:
            continue
        if isinstance(default, bool) or isinstance(default, int) and not isinstance(default, bool):
            if isinstance(default, bool):
                out[key] = raw.strip().lower() in ("1", "true", "yes", "on")
            else:
                out[key] = type(default)(int(raw, 0) if isinstance(default, int) else float(raw))
        elif isinstance(default, float):
            out[key] = float(raw)
        elif isinstance(default, list):
            out[key] = [int(x, 0) for x in raw.split(",") if x.strip()]
        else:
            out[key] = raw
    return out


@dataclass
class Config:
    values: dict[str, Any] = field(default_factory=lambda: dict(DEFAULTS))
    path: Optional[str] = None

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        merged = dict(DEFAULTS)
        used = path or (str(_config_path()) if _config_path() else None)
        if used:
            p = Path(used).expanduser()
            if p.is_file():
                merged.update(json.loads(p.read_text()))
        merged.update(_from_env())
        # 没在配置里写密钥时，退回配网落盘的那一份（见 provision.py）
        keys = data_dir() / "keys.json"
        if keys.is_file():
            try:
                auto = json.loads(keys.read_text())
                for k in ("net_key", "app_key", "dev_key", "node_addr"):
                    if not merged.get(k) and auto.get(k):
                        merged[k] = auto[k]
            except Exception:
                pass
        return cls(values=merged, path=used)

    def get(self, key: str) -> Any:
        return self.values[key]

    def hex_key(self, key: str) -> Optional[bytes]:
        v = self.values.get(key)
        return bytes.fromhex(v) if v else None

    def set(self, key: str, value: Any) -> None:
        """运行期校正（例如 $FSCCMD001$ 读到灯的真实单播地址后）"""
        self.values[key] = value

    def with_overrides(self, **kw: Any) -> "Config":
        clean = {k: v for k, v in kw.items() if v is not None}
        return Config(values={**self.values, **clean}, path=self.path)

    def dump(self) -> str:
        return json.dumps(self.values, indent=2, ensure_ascii=False)


# 数据文件（SEQ / roll / DeviceKey / 状态）——路径统一由这里给，别散在各模块
def data_file(name: str) -> Path:
    return data_dir() / name
