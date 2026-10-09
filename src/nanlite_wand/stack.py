#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""stack.py —— 蓝牙 Mesh 协议栈 + 南光/Feasycom 厂商层（传输无关）

职责边界：本模块只管「Mesh 网络/传输层怎么算」，**不碰任何硬件细节** —— 字节进出
全部走 `link.MeshLink` 接口。换成 ESP32 之类的硬件桥时只实现 MeshLink，这里不用改。

已实测确立的事实（详见 docs/PROTOCOL.md）：
  · 厂商模型：CID 0x1111、Model 0x1111；3 字节 opcode = 0xC0|(cmd&0x3F) ‖ CID 小端两字节
  · **驱动光的命令码是 C1 11 11**；C2 11 11 是状态/应答码（历史上把它当命令码，卡了两周）
  · 真正生效的载荷是 Feasycom「快速命令」8 字节，见 commands.py；
    老的 fullCmd（`0B|DIM(2)|02|02|OUT|CCT(2)|GM(2)|SRC`，首字节=长度）在 Wand 上
    **0 回包 0 生效**（opcode C0..CF 全扫过），只有别的机型吃它
  · 每次连接都必须先在 0xFFF0 做 TEA 认证（auth.py），不认证时灯照样解密并回显、但光不动
  · Mesh 有重放保护：SEQ 必须严格递增，所以 SEQ 持久化（config.data_file）
"""

from __future__ import annotations

import asyncio
import math
import time
from typing import Optional

from . import crypto as MC
from . import net as MN
from .config import Config, data_file

# App 里硬编码的厂商模型标识（Composition Data 实测一致）
VENDOR_CID = 0x1111
VENDOR_MODEL = 0x1111

OP_APPKEY_ADD, OP_APPKEY_STATUS = 0x8000, 0x8003
OP_MODEL_BIND, OP_MODEL_STATUS = 0x803D, 0x803E
OP_COMPOSITION_GET, OP_COMPOSITION_STATUS = 0x8008, 0x0002
OP_TTL_GET, OP_TTL_STATUS = 0x800C, 0x800E
OP_RELAY_GET, OP_RELAY_STATUS = 0x8026, 0x8028

CMD_CCT, CMD_HSI = 0x02, 0x03

SEQ_FILE = "seq.txt"
SEQ_START = 0x1000


def load_seq(start: int = SEQ_START) -> int:
    try:
        return max(int(data_file(SEQ_FILE).read_text().strip()), start)
    except Exception:
        return start


def save_seq(v: int) -> None:
    try:
        data_file(SEQ_FILE).write_text(str(v & 0xFFFFFF))
    except Exception:
        pass


def pack_key_indexes(net_idx: int, app_idx: int) -> bytes:
    """两个 12 位密钥索引压成 3 字节（复刻库 ConfigAppKeyAdd 的打包）

    字节码依据：
        buf.put(net[1])
        buf.put(((app[1] & 0xFF) << 4) | (net[0] & 0x0F))
        buf.put(((app[0] & 0xFF) << 4) | ((app[1] & 0xFF) >> 4))
    （net/app 是 index 的**大端**两字节）
    """
    net = (net_idx & 0xFFF).to_bytes(2, "big")
    app = (app_idx & 0xFFF).to_bytes(2, "big")
    return bytes([net[1],
                  ((app[1] & 0xFF) << 4) | (net[0] & 0x0F),
                  ((app[0] & 0xFF) << 4) | ((app[1] & 0xFF) >> 4)])


def hr(t: str) -> None:
    print("\n" + "=" * 78)
    print(f" {t}")
    print("=" * 78, flush=True)


# =====================================================================
# fullCmd 载荷（别的机型吃它；Wand 实测不驱动光，只留作对照实验）
# =====================================================================

# fullCmd 里的 DIM 字段标尺：0..65535 对应 0..100%（灯屏显示% = floor(wire/655.35)，
# 实测锚点 dim=1000 → 1%、dim=10000 → 15%）。
# 注意：**快速命令的亮度是 0–100 直值**，不吃这套换算，见 commands.py。
DIM_SCALE = 65535
DIM_MIN_WIRE = 0x0000
DIM_MAX_WIRE = 0xFFFF


def dim_to_wire(pct: float) -> int:
    """百分比(0–100) → 灯用的亮度值

    标尺实测确认：wire = floor(pct * 65535 / 100)，灯的显示% = floor(wire / 655.35)。
    实证：dim=1000 → 显示 1%；dim=10000 → 显示 15%；dim=50000 → 被精确接受并停住。
    """
    pct = max(0.0, min(100.0, float(pct)))
    v = int(round(pct * DIM_SCALE / 100.0))
    return max(DIM_MIN_WIRE, min(DIM_MAX_WIRE, v))


def cct_payload(dim: float, cct: int = 5600, gm: int = 0,
                out_mode: int = 1, source: int = 1,
                long_form: bool = True) -> bytes:
    """FLM_CCT 载荷 —— 默认输出 **JSON 模板的完整 11 字节**：

        0B | DIM(2) | 02 | 02 | OUTPUT_MODE(1) | CCT(2) | GM(2) | SOURCE_MODE(1)

    ★★ 2026-09-22 19:30 二次修正（推翻当天早些时候的结论）：
      第 1 字节 **就是载荷总长度**（老协议叫 ssize）。CCT=11 → 0x0B、HSI=8 → 0x08，
      与 assets/002006.json 里 cmdList 的字节数合计完全一致。

    ⚠️ 但"首字节是长度"这条**只对 fullCmd 成立**，快速命令的首字节是 rollCode。
       当年把 fullCmd 当成"长期不生效的头号根因"是错的 —— 真因是缺 TEA 认证 +
       opcode 该用 C1（见 docs/PROTOCOL.md 的结论演进）。本函数在 Wand 上实测
       0 回包 0 生效，留作跨机型对照。

    long_form=False 只保留作对照，别用于实际下发。
    """
    body = bytes([0x02, 0x02, out_mode & 0xFF]) + (cct & 0xFFFF).to_bytes(2, "big")
    if long_form:
        body = body + (gm & 0xFFFF).to_bytes(2, "big") + bytes([source & 0xFF])
    return bytes([0x0B]) + dim_to_wire(dim).to_bytes(2, "big") + body


def cct_payload_raw(dim_raw: int, cct: int = 5600, gm: int = 0,
                    out_mode: int = 1, source: int = 1,
                    long_form: bool = True) -> bytes:
    """同上，但直接给灯的原始亮度值（排查/探针用）"""
    body = bytes([0x02, 0x02, out_mode & 0xFF]) + (cct & 0xFFFF).to_bytes(2, "big")
    if long_form:
        body = body + (gm & 0xFFFF).to_bytes(2, "big") + bytes([source & 0xFF])
    return bytes([0x0B]) + (dim_raw & 0xFFFF).to_bytes(2, "big") + body


def hsi_payload(dim_pct: float, hue: int = 0, sat: int = 100) -> bytes:
    """FLM_HSI 载荷（8 字节，首字节 = 长度）

        08 | DIM(2) | 03 | 01 | HUE(2) | SAT(1)
    """
    body = bytes([0x03, 0x01]) + (hue % 360).to_bytes(2, "big") + bytes([sat & 0xFF])
    return bytes([0x08]) + dim_to_wire(dim_pct).to_bytes(2, "big") + body


def vendor_opcode(cmd: int, cid: int = VENDOR_CID) -> bytes:
    """3 字节厂商 opcode —— 复刻库里的 MeshParserUtils.createVendorOpCode

    字节码依据（AccessLayer.createCustomAccessMessage 调用它）：
        byte[] b = getOpCode(mOpCode);          // mOpCode = (cmd|0xC0)<<16
                                                //   → b = [0xC0|(cmd&0x3F), 0x00, 0x00]
        b[1] = (byte)(companyId & 0xFF);        // ★ 第 2 字节 = CID 低字节
        b[2] = (byte)((companyId >> 8) & 0xFF); // ★ 第 3 字节 = CID 高字节

    所以 FLM_CCT（cmd=0x02）+ CID 0x1111 的真实 opcode = C2 11 11，
    **不是** 单纯把 cmd 左移 16 位得到的 C2 00 00（后者会让灯的厂商模型认不出）。
    """
    return bytes([0xC0 | (cmd & 0x3F), cid & 0xFF, (cid >> 8) & 0xFF])


def vendor_access(cmd: int, payload: bytes, cid: int = VENDOR_CID) -> bytes:
    """厂商 AccessPDU = 3 字节 opcode ‖ 载荷"""
    return vendor_opcode(cmd, cid) + payload


# =====================================================================
# 会话
# =====================================================================

class WandSession:
    """一条与灯的会话：Mesh 编解码 + 发送 + 收帧解析（传输走 link，本类不碰硬件）"""

    def __init__(self, link, cfg: Optional[Config] = None):
        cfg = cfg or Config.load()
        self.link = link
        self.cfg = cfg
        MN.configure(cfg)          # 让 net.py 里的模块级默认值跟配置一致
        self.node = MN.MeshNode(
            net_key=cfg.hex_key("net_key") or MN.NET_KEY,
            app_key=cfg.hex_key("app_key") or MN.APP_KEY,
            dev_key=cfg.hex_key("dev_key") or MN.DEV_KEY,
            src=cfg.get("provisioner_addr"),
            iv_index=cfg.get("iv_index"),
            seq=load_seq(cfg.get("seq_start")),
            k2_impl="library",
        )
        self.frames: list[bytes] = []
        self.segs: dict[tuple, dict] = {}
        self.cursor = 0

    @property
    def dst(self) -> int:
        return self.cfg.get("node_addr")

    def _pump(self) -> None:
        """把链路上新收到的 PDU 取进本地缓冲（frames 只增不减，游标语义保持不变）"""
        self.frames.extend(self.link.pop_mesh_frames())

    # ---------- 发送 ----------
    async def send_one(self, frame: bytes, what: str) -> None:
        print(f"  → {what}\n      {frame.hex()}", flush=True)
        await self.link.send_mesh(frame)
        await asyncio.sleep(self.cfg.get("send_pace_s"))

    async def send_access(self, dst: int, access_pdu: bytes, akf: bool,
                          what: str, retry: int = 3,
                          gap: float = 1.2) -> None:
        """发一条访问消息；默认重发 3 次（Mesh 本身也靠重传保证可靠）。"""
        for attempt in range(retry):
            await self._send_once(dst, access_pdu, akf,
                                 what if retry == 1 else f"{what} [{attempt+1}/{retry}]")
            if attempt != retry - 1:
                await asyncio.sleep(gap)

    async def _send_once(self, dst: int, access_pdu: bytes, akf: bool,
                         what: str) -> None:
        node = self.node
        key = node.app_key if akf else node.dev_key
        seq0 = node.seq
        up_nonce = (bytes([0x01 if akf else 0x02, 0x00])
                    + seq0.to_bytes(3, "big")
                    + node.src.to_bytes(2, "big") + dst.to_bytes(2, "big")
                    + node.iv_index.to_bytes(4, "big"))
        up_ct = MC.aes_ccm_encrypt(key, up_nonce, access_pdu, mic_len=4)

        if len(up_ct) <= 15:
            # 未分段
            frame = node.build(dst, access_pdu, akf=akf, seq=seq0)
            node.seq = (seq0 + 1) & 0xFFFFFF     # ★ 手动推进，避免重放
            save_seq(node.seq)
            await self.send_one(frame, f"{what}（未分段，{len(frame)}B）")
            return

        # 分片
        chunk = 12
        n_seg = math.ceil(len(up_ct) / chunk)
        seq_zero = seq0 & 0x1FFF
        print(f"  {what}：上层传输 {len(up_ct)}B → 分 {n_seg} 片"
              f"（SeqZero={seq_zero}）")
        for i in range(n_seg):
            part = up_ct[i*chunk:(i+1)*chunk]
            o1 = (0 << 7) | ((seq_zero >> 6) & 0x7F)
            o2 = ((seq_zero & 0x3F) << 2) | ((i >> 3) & 0x03)
            o3 = ((i & 0x07) << 5) | ((n_seg - 1) & 0x1F)
            ltr = bytes([(1 << 7) | (0x40 if akf else 0x00)
                         | (node.aid if akf else 0), o1, o2, o3])
            # ★ 分片这里必须用 build_transport（别再二次加密/二次套头）
            frame = node.build_transport(dst, ltr + part)
            await self.send_one(frame, f"{what} 第 {i+1}/{n_seg} 片")
        save_seq(node.seq)
        await asyncio.sleep(0.2)

    def _scan(self, seen: int) -> tuple[list, int]:
        """解出 frames[seen:] 里的完整消息，返回 (结果, 新游标)。"""
        out: list = []
        self._pump()
        for r in self.frames[seen:]:
            if (r[0] & 0x3F) != MN.PROXY_TYPE_NETWORK:
                continue
            got = self.node.parse(r)
            if got is None:
                continue
            res = self._decode(got)
            if res is None:
                continue
            if res.get("segmented"):
                print(f"     · 分片 {res['have']}/{res['need']}…", flush=True)
                continue
            out.append(res)
            op = res["opcode"]
            print(f"  ← opcode {('0x%04X' % op) if op is not None else 'n/a'}"
                  f"  akf={res['akf']}  AccessPDU={res['access'].hex()}"
                  f"  参数={res['params'].hex()}", flush=True)
        return out, len(self.frames)

    def sweep(self) -> list:
        """非阻塞扫一遍已到的帧——灯主动推的状态帧只能这样抓到，心跳里调用。"""
        out, self.cursor = self._scan(self.cursor)
        return out

    async def drain(self, seconds: float) -> list[dict]:
        """只处理**新到**的帧（用持久游标，避免重复报告历史帧）"""
        out: list[dict] = []
        t0 = time.time()
        seen = self.cursor
        while time.time() - t0 < seconds:
            got, seen = self._scan(seen)
            out.extend(got)
            await asyncio.sleep(0.15)
        self.cursor = len(self.frames)
        print(f"  （本轮新帧 {len(out)}"
              f" 条解出；累计原始帧 {self.cursor}）", flush=True)
        return out

    def _decode(self, got: dict) -> Optional[dict]:
        tp = got["transport"]
        if got["ctl"] or not tp:
            return None
        lt0 = tp[0]
        if not (lt0 >> 7):
            return self._upper(tp[1:], (lt0 >> 6) & 1, got["seq"],
                               got["src"], got["dst"], 4)
        if len(tp) < 4:
            return None
        o1, o2, o3 = tp[1], tp[2], tp[3]
        szmic = o1 >> 7
        seqzero = ((o1 & 0x7F) << 6) | (o2 >> 2)
        sego = ((o2 & 0x03) << 3) | (o3 >> 5)
        segn = o3 & 0x1F
        k = (got["src"], seqzero)
        st = self.segs.setdefault(k, {"akf": (lt0 >> 6) & 1, "segn": segn,
                                      "szmic": szmic, "parts": {},
                                      "src": got["src"], "dst": got["dst"]})
        st["parts"][sego] = tp[4:]
        if len(st["parts"]) < segn + 1:
            return {"segmented": True, "have": len(st["parts"]), "need": segn + 1}
        full = b"".join(st["parts"][i] for i in range(segn + 1))
        self.segs.pop(k, None)
        return self._upper(full, st["akf"], seqzero, st["src"], st["dst"],
                           8 if szmic else 4)

    def _upper(self, ct: bytes, akf: int, seq: int, src: int, dst: int,
               mic: int) -> Optional[dict]:
        """★ nonce 里的 SRC 必须是**发送方**的地址（灯 0x0002），DST 是收方（我们 0x0001）。
        之前这里误用了 self.node.src 当 SRC，导致灯的回包一条都解不开、被静默丢弃。"""
        key = self.node.app_key if akf else self.node.dev_key
        nonce = (bytes([0x01 if akf else 0x02, 0x00])
                 + (seq & 0xFFFFFF).to_bytes(3, "big")
                 + src.to_bytes(2, "big") + dst.to_bytes(2, "big")
                 + self.node.iv_index.to_bytes(4, "big"))
        try:
            access = MC.aes_ccm_decrypt(key, nonce, ct, mic)
        except Exception:
            return None
        return {"akf": akf, "access": access, "opcode": MN.parse_opcode(access),
                "params": access[MN.opcode_len(access):]}
