#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""link.py —— 传输层接口：把「字节怎么进出灯」和「Mesh 协议怎么算」彻底分开

这是给后续硬件桥留的唯一接口。**换传输不需要动协议栈**：
`WandSession` 只依赖下面这五个方法，`BleProxyLink` 是 macOS/Linux 上跑通的实现（bleak）。
一块 ESP32-C3/S3 之类的桥只需要用 socket / 串口 / MQTT 实现同一个 `MeshLink`，
把 `0x2ADD 写 / 0x2ADE 通知` 换成"把 Mesh 网络 PDU 原样搬进搬出"，
把 `0xfff2 写 / 0xfff1 通知` 换成"把厂商认证字节流原样搬进搬出"，协议层无需改动。

三条通道的语义（都在同一条 BLE 连接上并存）：
    Mesh GATT Proxy   0x1828：写 0x2ADD / 通知 0x2ADE   —— Mesh 网络 PDU（不透明字节）
    Feasycom 私有     0x0FFF0：写 0xfff2 / 通知 0xfff1  —— TEA 认证 + $FSCCMD 诊断
    PB-GATT 配网      0x1827：写 0x2ADF / 通知 0x2AE0  —— 只在配网阶段用（见 provision.py）
"""

from __future__ import annotations

import asyncio
from typing import Optional, Protocol

PROXY_SVC = "00001828-0000-1000-8000-00805f9b34fb"
PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"
FEASY_WRITE = "0000fff2-0000-1000-8000-00805f9b34fb"
FEASY_NOTIFY = "0000fff1-0000-1000-8000-00805f9b34fb"


class MeshLink(Protocol):
    """运行时字节通道。实现者**不需要懂 Mesh**，只管把 PDU 原样搬进搬出。"""

    async def open(self) -> None: ...

    async def close(self) -> None: ...

    @property
    def connected(self) -> bool: ...

    async def send_mesh(self, frame: bytes) -> None: ...

    def pop_mesh_frames(self) -> list[bytes]:
        """取走并清空已收到的 Mesh 网络 PDU（非阻塞）"""
        ...

    async def send_vendor(self, payload: bytes) -> None: ...

    async def recv_vendor(self, timeout: float = 2.0) -> Optional[bytes]:
        """取一条厂商通道（0xfff1）的通知；超时返回 None"""
        ...


class BleProxyLink:
    """用 bleak 走 BLE GATT Proxy + Feasycom 0xFFF0 的实现（macOS 已实测）

    macOS 特别注意：碰蓝牙的进程必须有 `NSBluetoothAlwaysUsageDescription`，
    否则直接 SIGABRT —— 所以本项目的常驻/调试入口都用 .app 包起来跑，见 deploy/。
    """

    def __init__(self, target_name: str = "P24002", address: Optional[str] = None,
                 scan_seconds: float = 8.0, scan_tries: int = 4, log=print):
        self.target_name = target_name
        self.address = address
        self.scan_seconds = scan_seconds
        self.scan_tries = scan_tries
        self.log = log
        self.client = None
        self.mesh_frames: list[bytes] = []
        self.vendor_q: asyncio.Queue = asyncio.Queue()

    # ---------- 生命周期 ----------
    async def open(self) -> None:
        from bleak import BleakClient, BleakScanner

        addr = self.address
        if not addr:
            addr = await self._scan(BleakScanner)
        if not addr:
            raise ConnectionError(f"没找到名为 {self.target_name} 或带 Mesh Proxy 服务的设备")
        self.address = addr
        self.client = BleakClient(addr)
        await self.client.connect()
        self.log(f"  已连接 {addr}  MTU={getattr(self.client, 'mtu_size', None)}")
        await self.client.start_notify(PROXY_OUT, self._on_mesh)
        await asyncio.sleep(1.0)
        await self._print_beacons()
        # 把 Proxy 的接收名单清空：不过滤才会收到我们发出去的回显
        await self.client.write_gatt_char(PROXY_IN, bytes([0x02, 0x00, 0x01]),
                                          response=False)
        await asyncio.sleep(0.8)
        try:
            await self.client.start_notify(FEASY_NOTIFY, self._on_vendor)
        except Exception as e:
            self.log(f"  （厂商通道 {FEASY_NOTIFY[:6]}… 订阅失败：{e}）")

    async def close(self) -> None:
        if self.client:
            try:
                await self.client.disconnect()
            except Exception:
                pass
            self.client = None

    @property
    def connected(self) -> bool:
        return bool(self.client and self.client.is_connected)

    async def _scan(self, scanner_cls) -> Optional[str]:
        for attempt in range(self.scan_tries):
            found: dict[str, str] = {}

            def cb(dev, adv):
                n = adv.local_name or dev.name or ""
                uu = [u.lower() for u in (adv.service_uuids or [])]
                if self.target_name.lower() in n.lower() or PROXY_SVC in uu:
                    found[dev.address] = n

            sc = scanner_cls(detection_callback=cb)
            await sc.start()
            await asyncio.sleep(self.scan_seconds)
            await sc.stop()
            if found:
                return list(found)[0]
            self.log(f"  第 {attempt + 1} 次扫描没找到，重试…")
            await asyncio.sleep(2.0)
        return None

    async def _print_beacons(self) -> None:
        """连接后头几秒能读到灯自己的信标，用来确认 NetworkID 是不是我们的网络"""
        from . import net as NET
        for r in list(self.mesh_frames):
            if (r[0] & 0x3F) == 0x01:
                bt = r[1] if len(r) > 1 else -1
                kind = {0x00: "未配网信标", 0x01: "安全网络信标",
                        0x02: "私有信标"}.get(bt, f"未知类型 0x{bt:02X}")
                extra = ""
                if bt == 0x01 and len(r) >= 23 and NET.NET_KEY:
                    extra = (f"  NetworkID={r[3:11].hex()}"
                             f"（我们 k3={NET.k3(NET.NET_KEY).hex()}）"
                             f" IVIndex={r[11:15].hex()}")
                self.log(f"  灯的信标 类型=0x{bt:02X} {kind}{extra}")
        self.mesh_frames.clear()

    # ---------- 数据面 ----------
    def _on_mesh(self, _c, data: bytearray) -> None:
        self.mesh_frames.append(bytes(data))

    def _on_vendor(self, _c, data: bytearray) -> None:
        self.vendor_q.put_nowait(bytes(data))

    def pop_mesh_frames(self) -> list[bytes]:
        out, self.mesh_frames = self.mesh_frames, []
        return out

    async def send_mesh(self, frame: bytes) -> None:
        await self.client.write_gatt_char(PROXY_IN, frame, response=False)

    async def send_vendor(self, payload: bytes) -> None:
        await self.client.write_gatt_char(FEASY_WRITE, payload, response=False)

    async def recv_vendor(self, timeout: float = 2.0) -> Optional[bytes]:
        try:
            return await asyncio.wait_for(self.vendor_q.get(), timeout)
        except asyncio.TimeoutError:
            return None
