#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
provision.py —— Mac 端 SIG Mesh 配网器（阶段 1：把灯配进我们自己的网络）
============================================================================

依据
----
Mesh Profile 1.0 §5.4.2（配网密码学）+ PB-GATT 封装实测结论：
  · 每次写入/收到 = **Proxy PDU**（首字节 [SAR(2位)][类型(6位)]）
    类型 0x03 = Provisioning PDU。所以完整消息的首字节是 0x03。
  · 灯的 Provisioning Data Out 会回同样封装的消息。

流程（每步都打印原始字节，便于逐阶段核对）
----
  1. 连接 + 订阅 2ADC
  2. Invite        → Capabilities
  3. Start（No OOB）
  4. 发 Provisioner Public Key（67 字节）
  5. 收 Device Public Key（67 字节）→ 算 ECDH 共享密钥
  6. 两边各算 ConfirmationKey，交换 Confirmation
  7. 交换 Random，互相校验 Confirmation
  8. 派生 SessionKey/SessionNonce，加密下发 Provisioning Data
  9. 收 Provisioning Complete

ConfirmationInputs 组成（145 字节，**所有 PDU 类型字节都要排除**）：
    Invite参数(1) || Capabilities参数(11) || Start参数(5)
    || ProvisionerPublicKeyXY(64) || DevicePublicKeyXY(64)

安全与约束
----
  * 本脚本会**真的改变灯的状态**（配网成功即归入我们的网络）。
  * 失败可回退：重置灯 → 用 NANLINK App 重新配网。
  * 只做配网，不做后续配置（那是阶段 2 的事），保持阶段边界清晰。

用法：
    python3 -m nanlite_wand provision
    python3 -m nanlite_wand provision --sweep      # 自动试所有 (CiInputs × k1 顺序) 组合
    # macOS 上碰蓝牙的进程必须有 NSBluetoothAlwaysUsageDescription（否则 TCC 直接 SIGABRT），
    # 用 deploy/install-macos.sh 生成的 .app 身份跑，或给终端授予蓝牙权限

⚠️ 配网会**改变灯的归属**：配进你的网络后官方 App 就连不上这盏灯了；
   要还原就在灯上恢复出厂，再让 App 重新配一次。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time

from bleak import BleakClient, BleakScanner

from . import crypto as MC

# ── 目标与特征值 ─────────────────────────────────────────────────────
TARGET_NAME = os.environ.get("NANLITE_TARGET_NAME", "P24002")
PROV_SVC = "00001827-0000-1000-8000-00805f9b34fb"
PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"    # 主机 → 设备（write-without-response）
PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"   # 设备 → 主机（notify）

# ── 网络参数：来自 Config（没配就现生成随机密钥并落盘到数据目录 keys.json）──
#    换一盏灯 / 换一个人跑，密钥都不一样 —— 这正是"可复现"该有的样子：
#    流程可复现，而不是复用别人的密钥。
IV_INDEX = 0x00000000
FLAGS = 0x00
UNICAST_ADDR = 0x0002        # 我们（配网器）占 0x0001，给灯 0x0002

# ── Provisioning PDU 类型 ────────────────────────────────────────────
P_INVITE, P_CAPS, P_START, P_PUBKEY = 0x00, 0x01, 0x02, 0x03
P_INPUT_COMPLETE, P_CONFIRM, P_RANDOM, P_DATA = 0x04, 0x05, 0x06, 0x07
P_COMPLETE, P_FAILED = 0x08, 0x09

FAIL_NAMES = {0x01: "Invalid PDU", 0x02: "Invalid Format", 0x03: "Unexpected PDU",
              0x04: "Confirmation Value Failed", 0x05: "Out of Resources",
              0x06: "Decryption Failed", 0x07: "Unexpected Error",
              0x08: "Cannot Assign Addresses", 0x09: "Invalid Data"}

PROXY_PROV = 0x03   # Proxy PDU 类型：Provisioning PDU


# ── 配网后必须把 DeviceKey 存下来！它是从本次的 ECDH 推导的，
#    每次配网都不一样；控制脚本要靠它才能发 Config 消息（AKF=0）。
from .config import Config, data_file

KEYS_FILE = "keys.json"

NET_KEY: bytes | None = None        # 由 configure() 填
APP_KEY: bytes | None = None
KEY_INDEX = 0x0000
IV_INDEX = 0x00000000
FLAGS = 0x00
UNICAST_ADDR = 0x0002               # 配网器占 0x0001，给灯 0x0002


def configure(cfg: Config | None = None) -> Config:
    """把配置里的网络参数灌进模块级名字；缺密钥就现生成随机的一对并落盘。

    ⇒ 复现的是**流程**，不是别人的密钥：第一次跑本工具会自建一个全新的 Mesh 网络。
    """
    global NET_KEY, APP_KEY, KEY_INDEX, IV_INDEX, UNICAST_ADDR
    cfg = cfg or Config.load()
    NET_KEY = cfg.hex_key("net_key")
    APP_KEY = cfg.hex_key("app_key")
    if not NET_KEY or not APP_KEY:
        from .net import random_keys
        fresh = random_keys()
        NET_KEY = bytes.fromhex(fresh["net_key"])
        APP_KEY = bytes.fromhex(fresh["app_key"])
        _persist_keys(fresh)
        print(f"  生成新网络密钥 NetKey={NET_KEY.hex()}  AppKey={APP_KEY.hex()}")
        print(f"  （已写入 {data_file(KEYS_FILE)}；桥会自动读它）")
    KEY_INDEX = cfg.get("key_index")
    IV_INDEX = cfg.get("iv_index")
    UNICAST_ADDR = cfg.get("node_addr")
    return cfg


def _persist_keys(d: dict) -> None:
    try:
        old = {}
        f = data_file(KEYS_FILE)
        if f.is_file():
            old = json.loads(f.read_text())
        old.update(d)
        f.write_text(json.dumps(old, indent=2))
    except Exception:
        pass
DEVKEY_FILE = str(data_file("devkey.txt"))


def save_device_key(ecdh: bytes, prov_salt: bytes, extra: dict | None = None) -> bytes:
    """DeviceKey 每次配网都由本次 ECDH 现算，必须落盘，否则控制脚本解不开 Access 层"""
    dk = MC.k1(ecdh, prov_salt, b"prdk")
    try:
        data_file("devkey.txt").write_text(dk.hex())
        if extra:
            data_file(KEYS_FILE).write_text(json.dumps(extra, indent=2))
    except Exception:
        pass
    return dk


def hr(t: str) -> None:
    print("\n" + "=" * 78)
    print(f" {t}")
    print("=" * 78, flush=True)


class Provisioner:
    _addr_cache: str | None = None   # 跨实例复用，避免每次都重扫 12 秒

    def __init__(self, include_device_key: bool, attention: int, save_hex: bool,
                 burst: bool = True, ecdh_as_key: bool = False,
                 ci_variant: int = 1, ps_variant: int = 1, nonce_variant: int = 2):
        self.ecdh_as_key = ecdh_as_key
        self.ci_variant = ci_variant
        self.ps_variant = ps_variant
        self.nonce_variant = nonce_variant
        self.include_device_key = include_device_key
        self.attention = attention
        self.save_hex = save_hex
        self.burst = burst
        self.client: BleakClient | None = None
        self.inbox: list[bytes] = []
        self.trace: list[str] = []
        # 记录 PDU 参数（用于 ConfirmationInputs）
        self.par_invite = b""
        self.par_caps = b""
        self.par_start = b""

    # ---------- 低层收发 ----------
    def _log(self, s: str) -> None:
        print(s, flush=True)
        self.trace.append(s)

    def _on_notify(self, _c, data: bytearray) -> None:
        raw = bytes(data)
        ptype = raw[0] & 0x3F
        sar = (raw[0] >> 6) & 0x03
        self.inbox.append(raw)
        self._log(f"  ← 收 {len(raw)}B  SAR={sar} 类型=0x{ptype:02x}: {raw.hex()}")

    async def _write_pdu(self, pdu: bytes) -> None:
        """发一个 Provisioning PDU（自动加 Proxy 头 0x03）"""
        if self.client is None or not self.client.is_connected:
            self._log("  ✗ 连接已断（设备可能在拒绝我们的消息），无法继续")
            raise ConnectionError("device disconnected")
        frame = bytes([PROXY_PROV]) + pdu
        self._log(f"  → 发 {len(frame)}B: {frame.hex()}")
        try:
            await self.client.write_gatt_char(PROV_IN, frame, response=False)
        except Exception as e:
            self._log(f"  ✗ 写入失败: {type(e).__name__}: {e}")
            raise ConnectionError(str(e))

    async def _wait_pdu(self, want: int, timeout: float = 8.0) -> bytes | None:
        """等一个指定类型的 Provisioning PDU，返回其**参数部分**（去掉 Proxy 头和类型字节）"""
        t0 = time.time()
        while time.time() - t0 < timeout:
            for r in list(self.inbox):
                if len(r) >= 2 and (r[0] & 0x3F) == PROXY_PROV and r[1] == want:
                    if r[1] == P_FAILED and len(r) >= 3:
                        err = r[2]
                        self._log(f"  ✗ 设备报错: Provisioning Failed —— "
                                  f"{FAIL_NAMES.get(err, hex(err))}")
                    self.inbox.remove(r)
                    return r[2:]
                if len(r) >= 2 and (r[0] & 0x3F) == PROXY_PROV and r[1] == P_FAILED:
                    err = r[2] if len(r) > 2 else -1
                    self._log(f"  ✗ 设备报错: Provisioning Failed —— "
                              f"{FAIL_NAMES.get(err, hex(err))}")
                    self.inbox.remove(r)
                    return None
            await asyncio.sleep(0.2)
        self._log(f"  ✗ 等 0x{want:02x} 超时（{timeout}s）")
        return None

    # ---------- 主流程 ----------
    async def run(self) -> bool:
        hr("1. 扫描并连接")
        found = {}

        def cb(dev, adv):
            n = adv.local_name or dev.name or ""
            uuids = [u.lower() for u in (adv.service_uuids or [])]
            if TARGET_NAME.lower() in n.lower() or PROV_SVC in uuids:
                found[dev.address] = n

        wait = 5.0 if Provisioner._addr_cache else 12.0
        sc = BleakScanner(detection_callback=cb)
        await sc.start()
        await asyncio.sleep(wait)
        await sc.stop()
        if Provisioner._addr_cache:
            addr = Provisioner._addr_cache
            self._log(f"  复用已知地址: {addr}")
        elif found:
            addr = list(found)[0]
            Provisioner._addr_cache = addr
        else:
            self._log("  ✗ 没找到灯（确认已开机、且在附近）")
            return False
        self._log(f"  目标: {addr}  name={found[addr]!r}")

        self.client = BleakClient(addr)
        await self.client.connect()
        self._log(f"  已连接: {self.client.is_connected}")
        mtu = getattr(self.client, "mtu_size", None)
        self._log(f"  ATT MTU = {mtu}（单次写上限 {mtu - 3 if mtu else '未知'} 字节）")

        have = [s.uuid.lower() for s in self.client.services]
        if PROV_SVC not in have:
            self._log("  ✗ 没有 Mesh Provisioning 服务 —— 灯不在未配网状态")
            return False
        await self.client.start_notify(PROV_OUT, self._on_notify)
        self._log("  已订阅 Provisioning Data Out")
        await asyncio.sleep(0.5)

        # ---- 2. Invite → Capabilities ----
        hr("2. Invite → Capabilities")
        self.par_invite = bytes([self.attention])
        await self._write_pdu(bytes([P_INVITE]) + self.par_invite)
        caps = await self._wait_pdu(P_CAPS)
        if caps is None or len(caps) < 11:
            self._log("  ✗ 没拿到 Capabilities")
            return False
        self.par_caps = caps[:11]
        elems = caps[0]
        algos = int.from_bytes(caps[1:3], "big")
        pubkey_type = caps[3]
        soob = caps[4]
        oob_out_size, oob_in_size = caps[5], caps[7]
        self._log(f"  元素数={elems} 算法=0x{algos:04x} 公钥类型={pubkey_type} "
                  f"StaticOOB=0x{soob:02x} OutOOB={oob_out_size} InOOB={oob_in_size}")
        if algos & 0x0001 == 0:
            self._log("  ✗ 设备不支持 FIPS P-256，无法继续")
            return False
        if pubkey_type != 0:
            self._log("  ✗ 公钥类型不是 P-256")
            return False
        if soob or oob_out_size or oob_in_size:
            self._log("  ⚠ 设备似乎需要 OOB 认证，本脚本只实现了 No OOB，可能失败")
        else:
            self._log("  ✓ No OOB —— 可以直接配网")

        # ---- 3. Start ----
        hr("3. Provisioning Start（选 No OOB）")
        self.par_start = bytes([0x00,   # 算法 FIPS P-256
                                0x00,   # 公钥类型 P-256
                                0x00,   # 认证方式 No OOB
                                0x00,   # 认证动作
                                0x00])  # 认证长度
        await self._write_pdu(bytes([P_START]) + self.par_start)

        # ---- 4. 发我们的公钥 ----
        hr("4. 公钥交换")
        our_xy, our_priv = MC.gen_p256_keypair()
        self.our_xy = our_xy
        self._log(f"  本地公钥 X = {our_xy[:32].hex()}")
        self._log(f"  本地公钥 Y = {our_xy[32:].hex()}")
        await self._write_pdu(bytes([P_PUBKEY]) + our_xy)

        dev_xy = await self._wait_pdu(P_PUBKEY, timeout=20.0)
        if dev_xy is None or len(dev_xy) < 64:
            self._log("  ✗ 没收到设备公钥")
            return False
        dev_xy = dev_xy[:64]
        self._log(f"  设备公钥 X = {dev_xy[:32].hex()}")
        self._log(f"  设备公钥 Y = {dev_xy[32:].hex()}")

        self.dev_xy = dev_xy
        ecdh = MC.ecdh_shared_secret(our_priv, dev_xy)
        self._log(f"  ECDH 共享密钥 = {ecdh.hex()}")

        # ---- 5/6. Confirmation 与 Random 交换 ----
        # 实测：发完 Confirmation 后设备会立刻回它的 Confirmation；
        # 但收到我们的 Random 后无响应。最可能是 **无响应写被丢了**（没有确认机制）。
        # 所以：Confirmation 与 Random 连发，然后在任意顺序里收集设备的两个 PDU，
        #       收不全就**重发 Random**（最多 4 轮）。
        hr("5. Confirmation + Random 交换")
        INV, CAPS, ST, PKP, PKD = (self.par_invite, self.par_caps, self.par_start,
                                    self.our_xy, self.dev_xy)
        variants = {
            1: INV + CAPS + ST + PKP + PKD,                      # 规范：全部不含操作码 = 145
            2: b"\x00" + INV + CAPS + ST + PKP + PKD,             # Invite 含操作码 = 146
            3: INV + b"\x01" + CAPS + ST + PKP + PKD,             # Capabilities 含操作码 = 146
            4: b"\x00" + INV + b"\x01" + CAPS + b"\x02" + ST + PKP + PKD,  # 全部含操作码 = 148
            5: INV + CAPS + ST + PKD + PKP,                      # 公钥顺序颠倒 = 145
            6: CAPS + ST + PKP + PKD,                            # 不含 Invite = 144
            7: b"\x00" + INV + CAPS + ST + PKD + PKP,             # Invite 含操作码 + 公钥颠倒 = 146
        }
        conf_inputs = variants[self.ci_variant]
        self._log(f"  [CI 方案 v{self.ci_variant}] ConfirmationInputs（{len(conf_inputs)} 字节）= "
                  f"{conf_inputs.hex()}")
        if len(conf_inputs) != 145:
            self._log("  ⚠ 长度不是 145，请检查组成！")
        conf_salt = MC.confirmation_salt(conf_inputs)
        conf_key = MC.confirmation_key(conf_salt, ecdh)
        self._log(f"  ConfirmationSalt = {conf_salt.hex()}")
        self._log(f"  ConfirmationKey  = {conf_key.hex()}")

        rand_p = os.urandom(16)
        auth_value = bytes(16)      # No OOB
        conf_p = MC.confirmation_value(conf_key, rand_p, auth_value)
        self._log(f"  我方 Random       = {rand_p.hex()}")
        self._log(f"  我方 Confirmation = {conf_p.hex()}")

        if self.burst:
            self._log("  [burst 模式] Confirmation 与 Random 连发")
            await self._write_pdu(bytes([P_CONFIRM]) + conf_p)
            await asyncio.sleep(0.3)
            await self._write_pdu(bytes([P_RANDOM]) + rand_p)
        else:
            await self._write_pdu(bytes([P_CONFIRM]) + conf_p)
            await asyncio.sleep(0.5)
            await self._write_pdu(bytes([P_RANDOM]) + rand_p)

        dev_conf = dev_rand = None
        for attempt in range(4):
            t0 = time.time()
            while time.time() - t0 < 6.0:
                for r in list(self.inbox):
                    if len(r) < 3 or (r[0] & 0x3F) != PROXY_PROV:
                        continue
                    if r[1] == P_CONFIRM and dev_conf is None:
                        dev_conf = r[2:18]
                        self._log(f"  设备 Confirmation = {dev_conf.hex()}")
                        self.inbox.remove(r)
                    elif r[1] == P_RANDOM and dev_rand is None:
                        dev_rand = r[2:18]
                        self._log(f"  设备 Random       = {dev_rand.hex()}")
                        self.inbox.remove(r)
                    elif r[1] == P_FAILED:
                        err = r[2] if len(r) > 2 else -1
                        self._log(f"  ✗ 设备报错: {FAIL_NAMES.get(err, hex(err))}")
                        self.inbox.remove(r)
                        return False
                    else:
                        self.inbox.remove(r)
                if dev_conf and dev_rand:
                    break
                await asyncio.sleep(0.2)
            if dev_conf and dev_rand:
                break
            self._log(f"  · 第 {attempt+1} 轮未收全"
                      f"（conf={'有' if dev_conf else '无'} rand={'有' if dev_rand else '无'}）"
                      f"，重发 Random")
            await self._write_pdu(bytes([P_RANDOM]) + rand_p)

        if dev_conf is None or dev_rand is None:
            self._log("  ✗ 仍没拿到设备的 Confirmation/Random")
            return False

        expect = MC.confirmation_value(conf_key, dev_rand, auth_value)
        if expect != dev_conf:
            self._log("  ✗ 设备 Confirmation 校验失败！")
            self._log(f"     用我们的 ConfirmationKey 算出的期望值 = {expect.hex()}")
            self._log(f"     设备实际发来的                       = {dev_conf.hex()}")
            self._log("     → 说明 ConfirmationInputs 组成或 ECDH 有误（两边算出的 key 不同）")
            return False
        self._log("  ✓ 设备 Confirmation 校验通过 —— ECDH 与 ConfirmationInputs 都正确")

        # ---- 7. 派生会话密钥，下发 Provisioning Data ----
        hr("7. 下发 Provisioning Data")
        prov_salt = MC.provisioning_salt(conf_salt, rand_p, dev_rand, self.ps_variant)
        sk = MC.session_key(prov_salt, ecdh)
        sn_full = MC.k1(ecdh, prov_salt, b"prsn")
        sn = sn_full[3:16] if self.nonce_variant == 2 else sn_full[:13]
        self._log(f"  ProvisioningSalt = {prov_salt.hex()}")
        self._log(f"  SessionKey       = {sk.hex()}")
        self._log(f"  SessionNonce     = {sn.hex()}"
                  f"   （k1 全量 {sn_full.hex()}，取 [3:16]，方案 v{self.nonce_variant}）")

        pd = (NET_KEY
              + KEY_INDEX.to_bytes(2, "big")
              + bytes([FLAGS])
              + IV_INDEX.to_bytes(4, "big")
              + UNICAST_ADDR.to_bytes(2, "big"))
        if self.include_device_key:
            # 参考实现里出现过 Device key 日志；若规范版失败就打开这个开关再试
            pd = os.urandom(16) + pd
        self._log(f"  Provisioning Data 明文（{len(pd)} 字节）= {pd.hex()}")
        ct = MC.aes_ccm_encrypt(sk, sn, pd)
        self._log(f"  加密后（含 8 字节 MIC，{len(ct)} 字节）= {ct.hex()}")
        await self._write_pdu(bytes([P_DATA]) + ct)

        done = await self._wait_pdu(P_COMPLETE, timeout=20.0)
        if done is None:
            self._log("  ✗ 没收到 Provisioning Complete")
            if self.include_device_key:
                self._log("     （本次带了 Device Key，可关掉开关再试）")
            else:
                self._log("     （可打开 --include-device-key 再试，参考实现里有该字段的痕迹）")
            return False

        # ---- 成功 ----
        # ★ 变量名必须是本作用域里的 ecdh / prov_salt（曾经误写成 ECDH_SECRET/PROV_SALT，
        #   导致配网其实已成功、却在最后一步 NameError 崩掉、DeviceKey 没被保存 →
        #   控制脚本继续用旧 DeviceKey → 表现成"能连上但灯毫无反应"）。
        save_device_key(ecdh, prov_salt, extra={
            "net_key": NET_KEY.hex(), "app_key": APP_KEY.hex(),
            "dev_key": MC.k1(ecdh, prov_salt, b"prdk").hex(),
            "node_addr": UNICAST_ADDR})
        hr("★ 配网成功")
        print(f"  DeviceKey 已保存到 {DEVKEY_FILE}（控制脚本会自动读取）")
        self._log("  灯已归入我们自己的 Mesh 网络：")
        self._log(f"    NetKey        = {NET_KEY.hex()}")
        self._log(f"    AppKey        = {APP_KEY.hex()}")
        self._log(f"    灯的单播地址  = 0x{UNICAST_ADDR:04X}")
        self._log("  接下来：断开重连（灯此时应改为广播 Mesh Proxy 0x1828），")
        self._log("          然后进入阶段 2：读 Composition Data 拿厂商 Model ID。")
        return True

    async def close(self) -> None:
        if self.client:
            try:
                await self.client.disconnect()
            except Exception:
                pass
        if self.save_hex:
            p = str(data_file("provision-trace.txt"))
            with open(p, "w", encoding="utf-8") as f:
                f.write("\n".join(self.trace))
            print(f"\n  （完整字节轨迹已存到 {p}）")


async def main() -> None:
    ap = argparse.ArgumentParser(description="Nanlite Wand Mesh 配网器（阶段 1）")
    ap.add_argument("--include-device-key", action="store_true",
                    help="在 Provisioning Data 里额外带 16 字节 Device Key（默认不带）")
    ap.add_argument("--attention", type=int, default=0, help="Attention Duration 秒（默认 0）")
    ap.add_argument("--ci-variant", type=int, default=1, choices=range(1, 8),
                    help="ConfirmationInputs 的组成方案（1-7）")
    ap.add_argument("--ps-variant", type=int, default=1, choices=range(1, 5),
                    help="ProvisioningSalt 构造方案 1-4")
    ap.add_argument("--nonce-variant", type=int, default=2, choices=(1, 2),
                    help="SessionNonce 取法：2=后13字节 k1[3:16]（规范，默认）"
                         "，1=前13字节 k1[:13]（旧的错误写法）")
    ap.add_argument("--sweep-ps", action="store_true", help="扫描 ProvisioningSalt 的 4 种方案")
    ap.add_argument("--sweep", action="store_true",
                    help="自动依次尝试所有 (CiInputs 方案 × k1 顺序) 组合")
    ap.add_argument("--ecdh-as-key", action="store_true",
                    help="k1 按规范顺序：CMAC(key=ECDHSecret, msg=Salt)")
    ap.add_argument("--no-burst", action="store_true",
                    help="不用 burst 模式（改成 Confirmation 收到后再发 Random）")
    args = ap.parse_args()

    configure()          # 网络参数来自 Config；缺密钥会现生成并落盘

    if not MC.self_test_quick():
        print("  ✗ 密码学自检失败，中止")
        sys.exit(1)

    if args.sweep_ps:
        for v in range(1, 5):
            print("\n" + "#" * 78)
            print(f"# ProvisioningSalt 方案 v{v}")
            print("#" * 78)
            pv = Provisioner(args.include_device_key, args.attention, save_hex=(v == 1),
                             burst=not args.no_burst, ci_variant=args.ci_variant,
                             ps_variant=v)
            ok = False
            try:
                ok = await pv.run()
            except ConnectionError:
                ok = False
            except Exception as e:
                print(f"  ✗ 异常: {type(e).__name__}: {e}")
            finally:
                await pv.close()
            if ok:
                print(f"\n  ★★★ ProvisioningSalt 方案 v{v} 成功！")
                print("\n  结果: 成功")
                return
            await asyncio.sleep(1.5)
        print("\n  结果: 4 种方案都失败")
        return

    if args.sweep:
        combos = [(v, k) for k in (False, True) for v in range(1, 8)]
        print(f"  自动扫描 {len(combos)} 种组合（CI 方案 × k1 顺序）")
        for i, (v, k) in enumerate(combos, 1):
            print("\n" + "#" * 78)
            print(f"# 组合 {i}/{len(combos)}: CI 方案 v{v}, k1 {'规范顺序(ECDH当密钥)' if k else 'Salt当密钥'}")
            print("#" * 78)
            pv = Provisioner(args.include_device_key, args.attention, save_hex=(i == 1),
                             burst=not args.no_burst, ecdh_as_key=k, ci_variant=v,
                             nonce_variant=args.nonce_variant)
            ok = False
            try:
                ok = await pv.run()
            except ConnectionError:
                ok = False
            except Exception as e:
                print(f"  ✗ 异常: {type(e).__name__}: {e}")
            finally:
                await pv.close()
            if ok:
                print(f"\n  ★★★ 组合 {i} 成功：CI 方案 v{v}, k1 {'规范顺序' if k else 'Salt当密钥'}")
                print("     请把这两个参数记下来，后续阶段 2 一直沿用。")
                print("\n  结果: 成功")
                return
            await asyncio.sleep(1.5)
        print("\n  结果: 全部组合都失败")
        return

    pv = Provisioner(args.include_device_key, args.attention, save_hex=True,
                     burst=not args.no_burst, ecdh_as_key=args.ecdh_as_key,
                     ci_variant=args.ci_variant, ps_variant=args.ps_variant,
                     nonce_variant=args.nonce_variant)
    try:
        ok = await pv.run()
    except ConnectionError:
        ok = False
    except Exception as e:
        print(f'  ✗ 异常: {type(e).__name__}: {e}')
        ok = False
    finally:
        await pv.close()
    print("\n  结果:", "成功" if ok else "失败")


if __name__ == "__main__":
    asyncio.run(main())
