#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wand_bridge.py —— 常驻桥：Bluetooth SIG Mesh（南光 Wand）↔ MQTT

Homebridge 侧已经配好了（`~/.homebridge/config.json` 里的 mqttthing「南光 Wand
书桌灯」）。这个进程负责把 MQTT 指令翻成 Mesh 厂商指令，并把状态回写 MQTT。

话题契约（必须与 config.json 完全一致）：
    订阅  nanlite/wand/set/on                 "true"/"false"（或 1/0、ON/OFF）
          nanlite/wand/set/brightness         0..100
          nanlite/wand/set/colorTemperature   mired（HomeKit 单位；K = 1e6/mired）
          nanlite/wand/set/hue                0..360
          nanlite/wand/set/saturation         0..100
    发布  nanlite/wand/online                Online / Offline（retained）
          nanlite/wand/on                    true / false  （retained）
          nanlite/wand/brightness            0..100        （retained）
          nanlite/wand/hue / saturation / colorTemperature （retained）

关键实现要点（都是这几天实测踩出来的）：
  · 载荷**必须**是设备 JSON 里 `cmdList` 的完整字节数，首字节 = 该载荷总长度：
      色温 11B：0B | DIM(2) | 02 | 02 | OUTPUT_MODE | CCT(2) | GM(2) | SOURCE_MODE
      彩色  8B：08 | DIM(2) | 03 | 01 | HUE(2) | SAT(1)
    少一个字节（或长度字节对不上）灯会静默丢弃。
  · 亮度标尺 0..65535 = 0..100%，wire = round(pct * 65535 / 100)。
  · 灯**不上报状态**，也**不会**在渐变时发通知 ⇒ 这里回写的是**我们最后命令的值**。
  · 灯的光输出是缓慢渐变的（灯固件行为，载荷里没有渐变字段），
    但"目标值"是立刻改的 —— 所以 HomeKit 里看到的是目标值，这是能做到的最好语义。
  · SEQ 必须严格递增并持久化（Mesh 重放保护），已由 mesh_control 处理。
  · 一次拖动滑块 HomeKit 会连发多条 → 这里做**合并 + 去抖**，只发最后一条。
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import threading
import time

import paho.mqtt.client as mqtt

from . import net as MN
from . import stack as ST
from . import commands as CMD
from .auth import FeasyAuth
from .config import Config, data_file
from .link import BleProxyLink
from .stack import WandSession

# ── 默认值（都能被配置文件 / NANLITE_* 环境变量覆盖，见 config.py）──────
MQTT_HOST = "127.0.0.1"
MQTT_PORT = 1883
PREFIX = "nanlite/wand"
OFF_DIM = 0                 # 关灯用哪个亮度值：快速命令亮度是 0–100 直值，0 即关
DEBOUNCE = 0.10             # 合并滑块连发的等待
RESEND_GAP = 0.10           # 两条指令最小间隔
CCT_MIN, CCT_MAX = 2700, 6500

# 回声抑制的容差：HomeKit/mqttthing 会把我们刚发布的状态再当指令发回来。
# 与"上次发布值"相差不超过这个容差就当作回声忽略，否则会出现
# 「桥发布 hue → mqttthing 发回 set/hue → 桥又切到彩色模式」的死循环。
ECHO_TOL_BRI = 0
ECHO_TOL_CCT = 20      # K
ECHO_TOL_HUE = 2
ECHO_TOL_SAT = 2

# 启动时要不要立刻把状态下发一遍。
# 默认**不**下发：灯的渐变很慢，重启服务时擅自改灯会很突兀。
# 需要"启动即与 HomeKit 对齐"就把配置里的 sync_on_start 设为 true。
SYNC_ON_START = False        # 默认不在启动时动灯（由配置 sync_on_start 覆盖）

LOG = os.environ.get("NANLITE_BRIDGE_LOG") or str(data_file("bridge.log"))
STATE_FILE = str(data_file("state.json"))

# 维护模式开关：这个文件存在时，桥**完全不碰蓝牙**（只保持 MQTT + 状态页）。
# 用途：要单独跑配网/调试脚本时必须独占灯的 BLE 连接，
# 而 launchd 的 KeepAlive 会在 15 秒后把桥拉起来 → 用这个锁文件让它"起来但不连灯"。
MAINT_LOCK = str(data_file("maintenance.lock"))

# 一个极简的本地状态页（0.0.0.0:8080）。
# 用途：排查"手机能不能连到这台 Mac" —— 这个进程是 launchd 托管的常驻进程，
# 所以页面不会像临时起的测试服务器那样自己消失（踩过一次假失败的坑）。
# 也顺便当健康检查：curl http://<Mac的IP>:8080/
STATUS_HOST = "127.0.0.1"      # 默认只听本机；状态页是调试用的，不该暴露到局域网
STATUS_PORT = 0                # 0 = 不起状态页
_STATUS_BODY = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Nanlite Wand 桥 · 状态</title>
<style>body{{font:16px -apple-system,sans-serif;padding:24px;line-height:1.7}}
code{{background:#f2f2f2;padding:2px 6px;border-radius:4px}}
.ok{{color:#0a7d33;font-weight:600}}.bad{{color:#c00;font-weight:600}}</style>
<h2>{verdict}</h2>
<p>网络通路没问题：这台设备能连到运行着 Mesh 桥的 Mac。</p>
<hr>
<ul>
 <li>Mesh 连接：<b class="{mcls}">{mesh}</b></li>
 <li>MQTT：<b class="{qcls}">{mqtt}</b></li>
 <li>灯状态（最后命令值）：开={on} 亮度={bri}% 色温={cct}K 模式={mode}</li>
 <li>来自：<code>{peer}</code></li>
</ul>
<p style="color:#888;font-size:13px">Nanlite Wand Bridge · {ts}</p>
"""


async def status_server(bridge: "Bridge") -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
            line = head.split(b"\r\n", 1)[0].decode(errors="ignore")
            peer = writer.get_extra_info("peername")
            peer_s = f"{peer[0]}:{peer[1]}" if peer else "?"
            try:
                mesh_ok = bool(bridge.wand and bridge.wand.client.is_connected)
            except Exception:
                mesh_ok = False
            mqtt_ok = bridge.mqttc is not None
            st = bridge.st
            body = _STATUS_BODY.format(
                verdict="✅ 能连到 Mac",
                mesh="已连接" if mesh_ok else "未连接",
                mcls="ok" if mesh_ok else "bad",
                mqtt="已连接" if mqtt_ok else "未连接",
                qcls="ok" if mqtt_ok else "bad",
                on=st.on, bri=st.bri, cct=st.cct, mode=st.mode,
                peer=peer_s, ts=time.strftime("%Y-%m-%d %H:%M:%S"),
            ).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                         + f"Content-Length: {len(body)}\r\n".encode()
                         + b"Connection: close\r\n\r\n" + body)
            await writer.drain()
            log(f"状态页被访问：{line}  来自 {peer_s}")
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    srv = await asyncio.start_server(handle, STATUS_HOST, STATUS_PORT)
    log(f"状态页已启动：http://{STATUS_HOST}:{STATUS_PORT}/")
    async with srv:
        await srv.serve_forever()


def log(msg: str) -> None:
    now = time.time()
    line = f"[{time.strftime('%H:%M:%S', time.localtime(now))}.{int((now % 1) * 1000):03d}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ── 状态机 ──────────────────────────────────────────────────────────
class State:
    def __init__(self) -> None:
        self.on = True
        self.bri = 100          # 0..100
        self.cct = 5600         # K
        self.hue = 0
        self.sat = 0
        # 灯有两种互斥模式：CCT（色温）与 HSI（彩色）。
        # 只调亮度时要沿用上一次的模式，否则改亮度会把颜色重置掉。
        self.mode = "cct"
        self.last_bri = 100     # 关灯前的亮度，开灯时恢复

    def snapshot(self) -> dict:
        return {"on": self.on, "bri": self.bri, "cct": self.cct,
                "hue": self.hue, "sat": self.sat, "mode": self.mode}

    # 灯**不会上报状态**，所以"上次命令的值"必须自己持久化，
    # 否则每次服务重启 HomeKit 都会看到错的状态。
    def load(self) -> None:
        try:
            d = json.load(open(STATE_FILE))
            self.on = bool(d.get("on", self.on))
            self.bri = int(d.get("bri", self.bri))
            self.cct = int(d.get("cct", self.cct))
            self.hue = int(d.get("hue", self.hue))
            self.sat = int(d.get("sat", self.sat))
            self.mode = d.get("mode", self.mode)
            self.last_bri = int(d.get("last_bri", self.last_bri))
            log(f"恢复上次状态：{self.snapshot()}")
        except FileNotFoundError:
            pass
        except Exception as e:
            log(f"状态文件读取失败（用默认值）：{e}")

    def save(self) -> None:
        try:
            d = self.snapshot()
            d["last_bri"] = self.last_bri
            with open(STATE_FILE, "w") as f:
                json.dump(d, f)
        except Exception as e:
            log(f"状态文件写入失败：{e}")


# ── 桥 ──────────────────────────────────────────────────────────────
class Bridge:
    def __init__(self, cfg: Config | None = None) -> None:
        self.cfg = cfg or Config.load()
        global DEBOUNCE, RESEND_GAP, MQTT_HOST, MQTT_PORT, PREFIX, STATUS_HOST, STATUS_PORT
        global SYNC_ON_START, CCT_MIN, CCT_MAX
        DEBOUNCE = self.cfg.get("debounce_s")
        RESEND_GAP = self.cfg.get("resend_gap_s")
        MQTT_HOST = self.cfg.get("mqtt_host")
        MQTT_PORT = self.cfg.get("mqtt_port")
        PREFIX = self.cfg.get("topic_prefix")
        STATUS_HOST = self.cfg.get("status_host")
        STATUS_PORT = self.cfg.get("status_port")
        SYNC_ON_START = self.cfg.get("sync_on_start")
        CCT_MIN, CCT_MAX = CMD.RANGE[CMD.OPT_CCT]
        self.st = State()
        self.st.load()
        self.wand: WandSession | None = None
        self.dst = self.cfg.get("node_addr")   # 认证后由 $FSCCMD001$ 校正
        self.sent: dict[int, int] = {}   # 已下发的 option→值；没变的参数不再重发（降延迟）
        self.t_mqtt = time.time()
        self.is_discrete = False
        self.loop = asyncio.get_event_loop()
        self.wake = asyncio.Event()
        self.mqttc: mqtt.Client | None = None
        self.dirty = False
        self.stop = False
        self.published = {}
        self.selftest_req = False
        self.repair_req = False
        self.raw_req = None
        self.cfg_req = None

    # ---------- Mesh 侧 ----------
    async def ensure_mesh(self) -> bool:
        """连上灯的 Mesh Proxy；掉线自动重连"""
        if os.path.exists(MAINT_LOCK):
            if self.wand is not None:
                try:
                    await self.wand.link.close()
                except Exception:
                    pass
                self.wand = None
                self.publish_online(False)
                log("进入维护模式：已主动断开灯的连接")
            await asyncio.sleep(5.0)
            return False
        if self.wand is not None:
            try:
                if self.wand.link.connected:
                    return True
            except Exception:
                pass
        log("Mesh: 正在连接灯的 Proxy …")
        link = BleProxyLink(target_name=self.cfg.get("target_name"),
                            address=self.cfg.get("ble_address"), log=log)
        try:
            await link.open()
        except Exception as e:
            log(f"Mesh: 连接失败（{type(e).__name__}: {e}），5 秒后重试")
            self.publish_online(False)
            await asyncio.sleep(5.0)
            return False
        self.wand = WandSession(link, self.cfg)
        self.dst = await self.authenticate(self.wand)
        self.sent.clear()          # 新会话，"已下发值"缓存作废，否则会漏发
        self.publish_online(True)
        log(f"Mesh: 已连接   控制目标 = 0x{self.dst:04X}")
        return True

    async def authenticate(self, w) -> int:
        """每次连接都必须做：0xFFF0 上的 Feasycom TEA 认证。
        没做这一步，灯会照旧解开并回显我们的厂商帧，但**不驱动光**（实测两周的卡点）。

        返回灯的 Mesh 单播地址（$FSCCMD001$ → "$001-XXXX$"）；读不到就沿用配置值。
        """
        try:
            fa = FeasyAuth(w.link, rounds=self.cfg.get("tea_rounds"),
                           tea_key_hex=self.cfg.get("tea_key"))
            await fa.start()
            ok = await fa.authenticate(log=lambda *a: log("  认证: " + " ".join(str(x) for x in a)))
            addr, iv = await fa.query_all(log=lambda *a: log("  认证: " + " ".join(str(x) for x in a)))
            if not ok:
                log("⚠️ TEA 认证失败 —— 厂商命令会被灯收到但不生效，拔插灯的 USB-C 后重连")
            return addr if addr not in (None, 0x0000) else self.cfg.get("node_addr")
        except Exception as e:
            log(f"⚠️ TEA 认证异常：{type(e).__name__}: {e}")
            return self.cfg.get("node_addr")

    async def apply(self) -> None:
        """把当前状态下发到灯：Feasycom 快速命令（每条一个参数，rollCode 递增）

        ★ 2026-10-07 换掉的旧写法：`C2 11 11` + 11 字节 fullCmd —— 灯会回显但**不驱动光**。
          真因三条：缺 0xFFF0 的 TEA 认证、opcode 该用 C1（C2 是状态码，
          我们当时把载荷里的 FLM=0x02 当成 opcode 低字节）、首字节是 rollCode 不是长度。
        """
        assert self.wand is not None
        st = self.st
        dim = 0 if not st.on else st.bri
        cmds = [(CMD.OPT_DIM, dim, f"亮度{dim}%")]
        if st.mode == "hsi":
            cmds += [(CMD.OPT_HUE, int(st.hue) % 360, f"色相{st.hue}"),
                     (CMD.OPT_SAT, int(st.sat), f"饱和{st.sat}")]
            log("注意：色相/饱和在 Wand 上不驱动光（tint 模式进不去），仍照发以便跨机型复用")
        else:
            cmds += [(CMD.OPT_CCT, int(st.cct), f"色温{st.cct}K")]

        for option, value, label in cmds:
            if self.sent.get(option) == value:
                continue          # 没变的参数不再发：拖亮度时省掉一整条色温指令
            pdu = CMD.command(option, value)
            payload = pdu[3:]
            await self.wand.send_access(self.dst, pdu, akf=True, what=label,
                                        retry=1, gap=0.0)
            self.sent[option] = value
            log(f"下发: {label}  option=0x{option:02X} val={value} "
                f"roll=0x{payload[0]:02X} 帧={pdu.hex()}")
        ST.save_seq(self.wand.node.seq)

    async def _cfg(self, opcode, params, what, wait=10.0):
        await self.wand.send_access(self.cfg.get("node_addr"),
                                    MN.encode_opcode(opcode) + params,
                                    akf=False, what=what, retry=2, gap=1.2)
        return await self.wand.drain(wait)

    async def do_repair(self) -> None:
        """Config 层手术：重装 AppKey 并绑厂商模型（MQTT 主题 set/repair 触发）"""
        log("修复：开始重装 AppKey（Delete idx0 → Add idx0 → 绑模型）")
        from . import keysetup
        rep = await keysetup.install_app_key(self.wand, self.cfg,
                                            log=lambda *a: log(" ".join(str(x) for x in a)))
        self.pub(f"{PREFIX}/repair", " ".join(rep))
        log(f"修复完成：{' '.join(rep)}")

    async def do_selftest(self) -> None:
        log("自检：向灯发 Config Default TTL Get（DeviceKey 通道，应有回执）…")
        ok, detail = False, "无响应"
        try:
            await self.wand.send_access(self.cfg.get("node_addr"),
                                        MN.encode_opcode(0x800C),
                                        akf=False, what="自检 TTL Get",
                                        retry=2, gap=1.0)
            for m in await self.wand.drain(8.0):
                if m["opcode"] == 0x800E:
                    ok, detail = True, f"TTL={m['params'].hex()}"
                    break
        except Exception as e:
            detail = f"异常 {e}"
        self.pub(f"{PREFIX}/selftest", ("OK " + detail) if ok else ("FAIL " + detail))
        if ok:
            log(f"自检：✓ 灯在听（{detail}）—— 链路与应用层都正常")
        else:
            log(f"自检：✗ {detail} —— 灯的链路可能已死，建议拔插灯的 USB-C 复位")

    # ---------- MQTT ----------
    def publish_online(self, up: bool) -> None:
        self.pub(f"{PREFIX}/online", "Online" if up else "Offline")

    def pub(self, topic: str, value) -> None:
        if self.mqttc is None:
            return
        self.mqttc.publish(topic, str(value), retain=True)

    def publish_state(self) -> None:
        st = self.st
        self.pub(f"{PREFIX}/on", "true" if st.on else "false")
        self.pub(f"{PREFIX}/brightness", st.bri)
        if st.mode == "hsi":
            self.pub(f"{PREFIX}/hue", st.hue)
            self.pub(f"{PREFIX}/saturation", st.sat)
        else:
            # 色温模式下灯是"白"的，必须把 hue/sat 归零，
            # 否则 Home app 里色轮会停在上次的彩色上，和灯的实际状态矛盾。
            self.pub(f"{PREFIX}/hue", 0)
            self.pub(f"{PREFIX}/saturation", 0)
            self.pub(f"{PREFIX}/colorTemperature", round(1_000_000 / st.cct))
        # 记下我们刚发布的值，用来识别"回声"
        self.published = {"on": st.on, "bri": st.bri, "cct": st.cct,
                          "hue": st.hue if st.mode == "hsi" else 0,
                          "sat": st.sat if st.mode == "hsi" else 0}
        st.save()

    def _is_echo(self, field: str, value) -> bool:
        """这个值是不是我们刚发布出去的（回声）？"""
        p = self.published
        if field == "bri":
            return p.get("bri") is not None and abs(int(value) - p["bri"]) <= ECHO_TOL_BRI
        if field == "cct":
            return p.get("cct") is not None and abs(int(value) - p["cct"]) <= ECHO_TOL_CCT
        if field == "hue":
            d = abs(int(value) - (p.get("hue") or 0))
            return min(d, 360 - d) <= ECHO_TOL_HUE
        if field == "sat":
            return p.get("sat") is not None and abs(int(value) - p["sat"]) <= ECHO_TOL_SAT
        return False

    def on_mqtt(self, _c, _u, msg) -> None:
        topic, raw = msg.topic, (msg.payload or b"").decode(errors="ignore").strip()
        self.t_mqtt = time.time()
        self.is_discrete = topic.endswith("/set/on")   # 开关是离散点击，不必去抖
        st = self.st
        field = topic.split("/")[-1]
        try:
            if topic.endswith("/set/on"):
                on = raw.lower() in ("true", "1", "on", "yes")
                if on == st.on:
                    return
                if on and not st.on:
                    st.bri = st.last_bri or 100
                if not on and st.on:
                    st.last_bri = st.bri
                st.on = on
            elif topic.endswith("/set/brightness"):
                v = max(0, min(100, int(round(float(raw)))))
                if self._is_echo("bri", v):
                    return                      # 我们刚发布的值被 HomeKit 弹回来
                st.bri = v
                st.on = v > 0
                if st.on:
                    st.last_bri = v
            elif topic.endswith("/set/colorTemperature"):
                mired = float(raw)
                if mired <= 0:
                    return
                k = max(CCT_MIN, min(CCT_MAX, int(round(1_000_000 / mired))))
                if self._is_echo("cct", k):
                    return
                st.cct = k
                if st.mode != "cct":
                    log("模式切换 → 色温模式")
                st.mode = "cct"                 # 只由"真实的色温改动"驱动切换
                st.on = True
            elif topic.endswith("/set/hue"):
                v = int(round(float(raw))) % 360
                if self._is_echo("hue", v):
                    return
                st.hue = v
                if st.mode != "hsi":
                    log("模式切换 → 彩色模式")
                st.mode = "hsi"
                st.on = True
            elif topic.endswith("/set/saturation"):
                v = max(0, min(100, int(round(float(raw)))))
                if self._is_echo("sat", v):
                    return
                st.sat = v
                if st.mode != "hsi":
                    log("模式切换 → 彩色模式")
                st.mode = "hsi"
                st.on = True
            elif topic.endswith("/set/raw"):
                # 原始厂商帧注入：格式 "<厂商命令字节>:<载荷hex>"
                #   例 02:0bffff0202011388000001  → C2 11 11 + 该载荷
                # 用来在不重启桥的前提下扫字段组合（OUTPUT_MODE / SOURCE_MODE 等）。
                try:
                    parts = raw.split(":")
                    c, payload = parts[0], parts[1]
                    dst = int(parts[2], 16) if len(parts) > 2 and parts[2].strip() else self.cfg.get("node_addr")
                    self.raw_req = (int(c, 16), bytes.fromhex(payload.strip()), dst)
                    self.loop.call_soon_threadsafe(self.wake.set)
                    log(f"收到原始帧注入：cmd=0x{int(c,16):02X} 载荷={payload.strip()} dst=0x{dst:04X}")
                except Exception as e:
                    log(f"原始帧格式错误（应如 02:0bffff0202011388000001）：{e}")
                return
            elif topic.endswith("/set/cfg"):
                # 原始 Config 帧注入：<opcode_hex>:<参数hex>，走 DeviceKey 通道
                #   例 801b:020000c011111111  → Config Model Subscription Add
                try:
                    c, params = raw.split(":", 1)
                    self.cfg_req = (int(c, 16), bytes.fromhex(params.strip()))
                    self.loop.call_soon_threadsafe(self.wake.set)
                    log(f"收到 Config 注入：opcode=0x{int(c,16):04X} 参数={params.strip()}")
                except Exception as e:
                    log(f"Config 帧格式错误（应如 801b:020000c011111111）：{e}")
                return
            elif topic.endswith("/set/repair"):
                # 重装 AppKey：Delete idx0 → Add idx0 → Model App Bind idx0/1
                # 用于"Config 层有回执、但厂商指令毫无反应"的情况
                # （怀疑灯的 AppKey 值退回固件自带那把 → AID 校验不过 → 静默丢弃）。
                self.repair_req = True
                self.loop.call_soon_threadsafe(self.wake.set)
                return
            elif topic.endswith("/set/selftest"):
                # 让桥用它自己那条连接向灯发一条 Config 探针（有回执），
                # 用来判断"灯在应用层还活着吗"。不用另开连接抢灯。
                self.selftest_req = True
                self.loop.call_soon_threadsafe(self.wake.set)
                return
            else:
                return
        except ValueError:
            log(f"忽略非法取值 {topic} = {raw!r}")
            return

        log(f"MQTT: {field} = {raw}  → {st.snapshot()}")
        self.publish_state()
        self.loop.call_soon_threadsafe(self.wake.set)

    def start_mqtt(self) -> None:
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="nanlite-wand-bridge")
        c.on_message = self.on_mqtt
        c.connect(MQTT_HOST, MQTT_PORT, 30)
        for t in ("on", "brightness", "colorTemperature", "hue", "saturation",
                  "selftest", "repair", "raw", "cfg"):
            c.subscribe(f"{PREFIX}/set/{t}", qos=1)
        c.loop_start()
        self.mqttc = c
        log(f"MQTT: 已连 {MQTT_HOST}:{MQTT_PORT}，订阅 {PREFIX}/set/#")

    # ---------- 主循环 ----------
    async def run(self) -> None:
        # 首次连上后：把（持久化的）当前状态发布到 MQTT，让 HomeKit 立刻有值。
        # 是否顺带把灯也同步到这个状态，由配置 sync_on_start 决定（默认不）。
        while not self.stop:
            if await self.ensure_mesh():
                break
        self.publish_state()
        if SYNC_ON_START:
            try:
                await self.apply()
            except Exception as e:
                log(f"启动同步失败（忽略）：{e}")
        else:
            log("启动同步已关闭（sync_on_start=false）——只发布状态，不动灯")

        last_send = 0.0
        while not self.stop:
            if not await self.ensure_mesh():
                continue
            try:
                await asyncio.wait_for(self.wake.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                # 心跳：顺便检查连接，并把灯主动推来的帧扫掉（状态回读的唯一来源）
                try:
                    if not self.wand.link.connected:
                        log("Mesh: 连接已断开，准备重连")
                        self.wand = None
                        continue
                    for m in self.wand.sweep():
                        log(f"灯主动来帧：opcode=0x{m['opcode']:04X} "
                            f"akf={m['akf']} 参数={m['params'].hex()}")
                except Exception:
                    self.wand = None
                continue
            self.wake.clear()

            if self.cfg_req is not None:
                opc, params = self.cfg_req
                self.cfg_req = None
                log(f"Config 帧下发：opcode=0x{opc:04X} 参数={params.hex()}")
                await self.wand.send_access(self.cfg.get("node_addr"),
                                            MN.encode_opcode(opc) + params,
                                            akf=False, what=f"cfg 0x{opc:04X}",
                                            retry=2, gap=1.2)
                for m in await self.wand.drain(12.0):
                    log(f"  ← 灯回包 opcode=0x{m['opcode']:04X} 参数={m['params'].hex()}")
                continue

            if self.raw_req is not None:
                cmd, payload, dst = self.raw_req
                self.raw_req = None
                pdu = ST.vendor_access(cmd, payload)
                log(f"原始帧下发：cmd=0x{cmd:02X} dst=0x{dst:04X} AccessPDU={pdu.hex()}")
                await self.wand.send_access(dst, pdu, akf=True,
                                            what=f"raw cmd=0x{cmd:02X}", retry=1, gap=0.0)
                got = await self.wand.drain(14.0)   # 回包可能延迟 10s+，窗口要长
                real = [m for m in got if m["opcode"] is not None]
                if real:
                    for m in real:
                        log(f"  ← 灯回包 opcode=0x{m['opcode']:04X} 参数={m['params'].hex()}")
                else:
                    log("  ← 14 秒内灯无回包")
                continue

            if self.repair_req:
                self.repair_req = False
                await self.do_repair()
                continue

            if self.selftest_req:
                self.selftest_req = False
                await self.do_selftest()
                continue

            # 去抖：等一会儿，把滑块连发的多条合并成一条；开关点击不等
            t_wake = time.time()
            if not self.is_discrete:
                await asyncio.sleep(DEBOUNCE)
            self.wake.clear()
            t_debias = time.time()

            gap = RESEND_GAP - (time.time() - last_send)
            if gap > 0:
                await asyncio.sleep(gap)
            t_gap = time.time()
            try:
                await self.apply()
                last_send = time.time()
                log(f"时延：MQTT→唤醒 {1000*(t_wake-self.t_mqtt):.0f}ms"
                    f" + 去抖 {1000*(t_debias-t_wake):.0f}ms"
                    f" + 节流 {1000*(t_gap-t_debias):.0f}ms"
                    f" + 下发 {1000*(last_send-t_gap):.0f}ms"
                    f" = {1000*(last_send-self.t_mqtt):.0f}ms（桥内合计）")
            except Exception as e:
                log(f"下发失败：{e} —— 将在下一轮重连")
                self.wand = None


async def amain() -> None:
    b = Bridge()

    def bye(*_a):
        b.stop = True
        b.wake.set()

    signal.signal(signal.SIGINT, bye)
    signal.signal(signal.SIGTERM, bye)

    b.start_mqtt()
    asyncio.create_task(status_server(b))
    log("桥已启动")
    await b.run()
    log("桥已退出")
    if b.mqttc:
        b.publish_online(False)
        b.mqttc.loop_stop()
    if b.wand and b.wand.client:
        try:
            await b.wand.client.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(amain())
