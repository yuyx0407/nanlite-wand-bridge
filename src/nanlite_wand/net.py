#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
net.py —— SIG Mesh 网络层 / 上层传输层（阶段 2 的地基）
============================================================

全部算法都从南光 App 用的 FeasyMesh 库字节码里逐条读出来核对过，不是凭记忆：

    SecureUtils.calculateSalt(M)   = AES-CMAC(key=16×0x00, msg=M)          → s1(M)
    SecureUtils.calculateCMAC(a, b) = AES-CMAC(key=b, msg=a)    ★注意参数顺序
    SecureUtils.calculateK1(N,S,P)  = calculateCMAC(P, calculateCMAC(N, S))
    SecureUtils.calculateK2(N, P)   = calculateCMAC(P||0x00/0x02/0x03, calculateCMAC(N, s1("smk2")))
    SecureUtils.calculateK3(N)      = calculateCMAC("id64"||0x01, calculateCMAC(N, s1("smk3")))[0:8]
    SecureUtils.calculateK4(N)      = calculateCMAC("id6" ||0x01, calculateCMAC(N, s1("smk4")))
    SecureUtils.encryptCCM(data, key, nonce, mic)
    SecureUtils.encryptWithAES(data, key)      → 单块 AES-ECB
    SecureUtils.getNetMicLength(ctl)  : ctl==0 → 4, 否则 8
    SecureUtils.getTransMicLength(ctl): ctl==0 → 4, 否则 8

常量（SecureUtils.<clinit>）：
    SALT_KEY = 16×0x00        SMK2="smk2"  SMK3="smk3"  SMK4="smk4"
    SMK3_DATA="id64"          SMK4_DATA="id6"
    K2_MASTER_INPUT = {0x00}  PRCK/PRSK/PRSN/PRDK = "prck"/"prsk"/"prsn"/"prdk"

━━ 发出去的一整帧（就是 Proxy Data In 的内容）━━
    [0x00]                      ← Proxy PDU 类型：Network PDU
    [IVI<<7 | NID]              ← IVI = IVIndex & 1
    [ (CTL<<7|TTL || SEQ(3) || SRC(2)) XOR PECB[0:6] ]      ← 6 字节头混淆
    [ AES-CCM_EncKey(网络nonce, DST(2)||TransportPDU, mic) ] ← 密文||MIC

    NID     = k2(NetKey)[15] & 0x7F    EncKey = k2(NetKey, 0x01)
    PrivKey = k2(NetKey, 0x02)         AID    = k4(AppKey)
    PECB          = AES-ECB(PrivKey, 5×0x00 || IVIndex(4) || PrivacyRandom(7))
    PrivacyRandom = 密文（含 MIC）的前 7 字节              ← 不是另生成的随机数
    网络nonce(13B)= 0x00 || (CTL<<7|TTL) || SEQ(3) || SRC(2) || 0x0000 || IVIndex(4)
    mic           = ctl==0 ? 4 : 8

━━ 上层传输 ━━
    TransportPDU = 1 字节「下层传输头」+ 上层传输密文
    下层传输头（未分段访问消息）= (SEG<<7) | (AKF<<6) | AID     SEG=0
    上层传输密文 = AES-CCM(key, 上层nonce, AccessPDU, 4)
        AccessPDU = opcode || 参数
        上层nonce(13B) = 类型 || (CTL<<7) || SEQ(3) || SRC(2) || DST(2) || IVIndex(4)
        类型 = 0x01 用 AppKey（AKF=1） / 0x02 用 DeviceKey（AKF=0）
        ★ createApplicationNonce 只把 ctl 左移 7 位，**TTL 位当 0**；
          而网络层 nonce 用的是真实的 CTL<<7|TTL。参考实现如此，照抄。

因为帧结构是无歧义的（7 字节明文头 + 剩余全是密文），解析时不需要猜长度。
"""

from __future__ import annotations

from typing import Optional, Tuple

from . import crypto as MC

# ── 我们自己的网络（与 mesh_provision.py / firmware 一致）────────────────
# ⚠️ 下面三把是**示例值**（换任何人都必须重新生成 —— 配网时会话密钥由 ECDH 现算，
#    DeviceKey 也是每次配网都不同）。真正生效的值一律来自 Config / 数据目录，
#    由 configure() 覆盖这里；`nanlite-wand provision` 会自动随机生成并落盘。
NET_KEY = bytes.fromhex("00000000000000000000000000000001")   # 示例，不是任何人的真网
APP_KEY = bytes.fromhex("00000000000000000000000000000002")   # 示例
DEV_KEY = bytes.fromhex("00000000000000000000000000000003")   # 示例
KEY_INDEX = 0x0000
IV_INDEX = 0x00000000


def configure(cfg) -> None:
    """让模块级默认值与配置一致（老代码里 MN.NET_KEY / NODE_ADDR 等引用不用改）"""
    global NET_KEY, APP_KEY, DEV_KEY, KEY_INDEX, IV_INDEX, NODE_ADDR, PROVISIONER_ADDR
    NET_KEY = cfg.hex_key("net_key") or NET_KEY
    APP_KEY = cfg.hex_key("app_key") or APP_KEY
    DEV_KEY = cfg.hex_key("dev_key") or DEV_KEY
    KEY_INDEX = cfg.get("key_index")
    IV_INDEX = cfg.get("iv_index")
    NODE_ADDR = cfg.get("node_addr")
    PROVISIONER_ADDR = cfg.get("provisioner_addr")


def random_keys() -> dict:
    """新建 Mesh 网络用的一次性随机密钥"""
    import secrets
    return {"net_key": secrets.token_hex(16), "app_key": secrets.token_hex(16)}
FLAGS = 0x00
PROVISIONER_ADDR = 0x0001
NODE_ADDR = 0x0002

# ── SecureUtils 常量 ─────────────────────────────────────────────────
SALT_KEY = bytes(16)
K2_MASTER_INPUT = b"\x00"
SMK2, SMK3, SMK4 = b"smk2", b"smk3", b"smk4"
SMK3_DATA, SMK4_DATA = b"id64", b"id6"
PRCK, PRSK, PRSN, PRDK = b"prck", b"prsk", b"prsn", b"prdk"

# ── Proxy PDU 类型 ───────────────────────────────────────────────────
PROXY_TYPE_NETWORK = 0x00
PROXY_TYPE_PROXY_CFG = 0x02
PROXY_TYPE_PROVISIONING = 0x03

# ── 访问层 opcode ────────────────────────────────────────────────────
OP_COMPOSITION_DATA_GET = 0x8008
OP_COMPOSITION_DATA_STATUS = 0x02
OP_APPKEY_ADD = 0x8000
OP_APPKEY_STATUS = 0x8003
OP_MODEL_APP_BIND = 0x803D
OP_MODEL_APP_STATUS = 0x803E
OP_NODE_RESET = 0x8049
OP_NODE_RESET_STATUS = 0x804A


# =====================================================================
# 密钥派生
# =====================================================================

def cmac(a: bytes, b: bytes) -> bytes:
    """复刻 SecureUtils.calculateCMAC(a, b) = AES-CMAC(key = b, msg = a)"""
    return MC.aes_cmac(b, a)


def aes_salt(m: bytes) -> bytes:
    """s1(M) = AES-CMAC(key = 16×0x00, msg = M)"""
    return MC.aes_cmac(SALT_KEY, m)


def k2(n: bytes, p_byte: int = 0x00) -> Tuple[int, bytes, bytes]:
    """k2(NetKey) → (NID, EncryptionKey, PrivacyKey)　【规范写法】

    规范：k2(N,P) = AES-CMAC(AES-CMAC(s1("smk2"), N), 0x02 || P)
          NID 用 P=0x00、EncKey 用 P=0x01、PrivKey 用 P=0x02
    """
    inner = cmac(n, aes_salt(SMK2))
    out_nid = cmac(K2_MASTER_INPUT + b"\x00", inner)
    enc = cmac(K2_MASTER_INPUT + b"\x02", inner)
    priv = cmac(K2_MASTER_INPUT + b"\x03", inner)
    return out_nid[15] & 0x7F, enc, priv


def k2_library(n: bytes, p: bytes = K2_MASTER_INPUT) -> Tuple[int, bytes, bytes]:
    """k2(NetKey) → (NID, EncryptionKey, PrivKey)　【FeasyMesh 库的实际写法】

    ★ 这是南光 App 里 SecureUtils.calculateK2 的原样复刻 —— 它**不是**规范写法，
      而是把上一次 CMAC 的输出接进下一次的消息里（链式）：

          inner = encryptCCM(key = s1("smk2"), msg = N)
          t1    = encryptCCM(key = inner, msg = P || 0x01)          → NID = t1[15] & 0x7F
          t2    = encryptCCM(key = inner, msg = t1 || P || 0x02)    → EncryptionKey
          t3    = encryptCCM(key = inner, msg = t2 || P || 0x03)    → PrivacyKey

      字节码依据（dex_netlayer.txt 3088-3143）：
          3092  calculateCMAC(v5=N, v0=s1(SMK2)) → v5   ; inner
          3096  array-length v1, v6  ; v2 = 1 ; add-int/2addr v1, v2   ; len(P)+1
          3101  put(v0 = 空数组) 3102 put(v6 = P) 3103 put((byte)1)
          3106  calculateCMAC(那个, v5) → v0           ; t1 = P||0x01
          3109  aget-byte v1, v0, 15 ; and-int/lit8 127 ; → NID
          3112  array-length v3, v0  ← 注意：把**上一次的输出**算进长度
          3118  put(v0) 3119 put(v6=P) 3121 put((byte)2)
          3124  calculateCMAC(那个, v5) → v0           ; EncKey = t1||P||0x02
          3132  put(v0) 3133 put(v6=P) 3135 put((byte)3)
          3138  calculateCMAC(那个, v5) → v5           ; PrivKey = t2||P||0x03

      App 用这份代码能正常控制这盏灯 → 灯里跑的就是同一套推导，
      所以这里必须照抄，而不是照规范。
    """
    inner = cmac(n, aes_salt(SMK2))
    t1 = cmac(p + b"\x01", inner)
    nid = t1[15] & 0x7F
    enc = cmac(t1 + p + b"\x02", inner)
    priv = cmac(enc + p + b"\x03", inner)
    return nid, enc, priv


def k3(n: bytes) -> bytes:
    """k3(N) → 8 字节 Network ID

    ★ 取的是 CMAC 输出的**后 8 字节**，不是前 8 字节。
      calculateK3 字节码最后几行：
          const/16 v0, 8
          new-array v1, v0, [B      ; 目标 8 字节
          array-length v2, v4
          sub-int/2addr v2, v0      ; ← srcPos = 16 - 8 = 8
          arraycopy(v4, v2, v1, 0, v0)
      和 SessionNonce 一样是「取尾巴」的写法。

      实测印证：用本网络的 NetKey 算出的后 8 字节 = 5ae31cfb5e7557ba，
      与灯广播的安全网络信标里的 Network ID **完全一致**；
      用同一个 NetKey 算出的信标认证值 = d765d3dc86ed7753，也与灯广播一致。
    """
    return cmac(SMK3_DATA + b"\x01", cmac(n, aes_salt(SMK3)))[8:16]


def k4(n: bytes) -> int:
    """k4(N) → AID（一字节的低 6 位）"""
    return cmac(SMK4_DATA + b"\x01", cmac(n, aes_salt(SMK4)))[15] & 0x3F


def device_key(ecdh_secret: bytes, prov_salt: bytes) -> bytes:
    """DeviceKey = k1(ECDHSecret, ProvisioningSalt, "prdk")

    注意：Provisioning Data 里**不传** DeviceKey，两边各自推导。
    """
    return MC.k1(ecdh_secret, prov_salt, PRDK)


def encrypt_with_aes(data: bytes, key: bytes) -> bytes:
    """单块 AES-ECB（SecureUtils.encryptWithAES(data, key)）"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return (enc.update(data) + enc.finalize())[:len(data)]


# =====================================================================
# MeshNode
# =====================================================================

class MeshNode:
    """扮演 Mesh 网络里的「配网器」角色（单播地址 0x0001）。"""

    def __init__(self, net_key: bytes = NET_KEY, app_key: bytes = APP_KEY,
                 dev_key: Optional[bytes] = None, src: int = PROVISIONER_ADDR,
                 iv_index: int = IV_INDEX, seq: int = 0x000001,
                 k2_impl: str = "library"):
        self.net_key = net_key
        self.app_key = app_key
        self.dev_key = dev_key
        self.src = src
        self.iv_index = iv_index
        self.seq = seq
        self.k2_impl = k2_impl
        fn = k2_library if k2_impl == "library" else k2
        self.nid, self.enc_key, self.priv_key = fn(net_key)
        self.aid = k4(app_key)

    @staticmethod
    def _u16(v: int) -> bytes:
        return v.to_bytes(2, "big")

    @staticmethod
    def _u24(v: int) -> bytes:
        return (v & 0xFFFFFF).to_bytes(3, "big")

    def next_seq(self) -> int:
        s = self.seq
        self.seq = (self.seq + 1) & 0xFFFFFF
        return s

    def info(self) -> str:
        return (f"NID=0x{self.nid:02X}  AID=0x{self.aid:02X}  "
                f"NetworkID={k3(self.net_key).hex()}\n"
                f"  EncKey  = {self.enc_key.hex()}\n"
                f"  PrivKey = {self.priv_key.hex()}\n"
                f"  本机地址 = 0x{self.src:04X}   IVIndex = {self.iv_index}"
                + (f"\n  DevKey  = {self.dev_key.hex()}" if self.dev_key else ""))

    # ---------- 组帧 ----------
    def build(self, dst: int, access_pdu: bytes, *, akf: bool,
              key: Optional[bytes] = None, ctl: int = 0, ttl: int = 5,
              seq: Optional[int] = None, access_ttl_zero: bool = True) -> bytes:
        if seq is None:
            seq = self.next_seq()
        if key is None:
            key = self.app_key if akf else self.dev_key
        if key is None:
            raise ValueError("没有可用的加密密钥（akf=False 时必须给 DeviceKey）")

        # 1) 上层传输
        #    access_ttl_zero=True 时上层 nonce 的 TTL 位当 0（参考实现的写法）
        up_ctl_ttl = ((ctl << 7) | (ttl & 0x7F)) & 0xFF if not access_ttl_zero \
            else ((ctl << 7) & 0x80)
        up_nonce = (bytes([0x01 if akf else 0x02, up_ctl_ttl])
                    + self._u24(seq) + self._u16(self.src) + self._u16(dst)
                    + self.iv_index.to_bytes(4, "big"))
        up_ct = MC.aes_ccm_encrypt(key, up_nonce, access_pdu, mic_len=4)

        # 2) 下层传输头（未分段）
        lt_header = bytes([(0x40 if akf else 0x00) | (self.aid if akf else 0)])
        transport_pdu = lt_header + up_ct

        # 3) 网络层
        ctl_ttl = ((ctl << 7) | (ttl & 0x7F)) & 0xFF
        net_nonce = (b"\x00" + bytes([ctl_ttl]) + self._u24(seq)
                     + self._u16(self.src) + b"\x00\x00"
                     + self.iv_index.to_bytes(4, "big"))
        net_ct = MC.aes_ccm_encrypt(self.enc_key, net_nonce,
                                    self._u16(dst) + transport_pdu,
                                    mic_len=8 if ctl else 4)

        # 4) 头混淆
        pecb = encrypt_with_aes(b"\x00" * 5
                                + self.iv_index.to_bytes(4, "big")
                                + net_ct[:7], self.priv_key)
        plain_header = bytes([ctl_ttl]) + self._u24(seq) + self._u16(self.src)
        obf = bytes(a ^ b for a, b in zip(plain_header, pecb[:6]))

        ivi_nid = ((self.iv_index & 1) << 7) | self.nid
        return bytes([PROXY_TYPE_NETWORK, ivi_nid]) + obf + net_ct
    def build_transport(self, dst: int, transport_pdu: bytes, *,
                        ctl: int = 0, ttl: int = 5,
                        seq: Optional[int] = None) -> bytes:
        """★ 直接封装一个**已经组好的 TransportPDU**（下层头 + 已加密的上层传输）。

        普通的 build() 吃的是「AccessPDU」，会自己做上层加密 + 套下层头。
        分片发送时我们**必须**自己拼下层头（因为它含分片字段），
        所以不能再走 build()，否则会被二次加密 + 二次套头 —— 灯就解不开了。
        """
        if seq is None:
            seq = self.next_seq()
        ctl_ttl = ((ctl << 7) | (ttl & 0x7F)) & 0xFF
        net_nonce = (b"\x00" + bytes([ctl_ttl]) + self._u24(seq)
                     + self._u16(self.src) + b"\x00\x00"
                     + self.iv_index.to_bytes(4, "big"))
        net_ct = MC.aes_ccm_encrypt(self.enc_key, net_nonce,
                                    self._u16(dst) + transport_pdu,
                                    mic_len=8 if ctl else 4)
        pecb = encrypt_with_aes(b"\x00" * 5
                                + self.iv_index.to_bytes(4, "big")
                                + net_ct[:7], self.priv_key)
        plain_header = bytes([ctl_ttl]) + self._u24(seq) + self._u16(self.src)
        obf = bytes(a ^ b for a, b in zip(plain_header, pecb[:6]))
        ivi_nid = ((self.iv_index & 1) << 7) | self.nid
        return bytes([PROXY_TYPE_NETWORK, ivi_nid]) + obf + net_ct

    # ---------- 解帧 ----------
    def parse(self, frame: bytes) -> Optional[dict]:
        """解开一条收到的 Proxy 帧。帧结构无歧义：头 7 字节 + 余下全是密文。"""
        if len(frame) < 7 + 2 + 4:
            return None
        if (frame[0] & 0x3F) != PROXY_TYPE_NETWORK:
            return None
        body = frame[1:]
        if (body[0] & 0x7F) != self.nid:
            return None
        obf, net_ct = body[1:7], body[7:]

        pecb = encrypt_with_aes(b"\x00" * 5
                                + self.iv_index.to_bytes(4, "big")
                                + net_ct[:7], self.priv_key)
        hdr = bytes(a ^ b for a, b in zip(obf, pecb[:6]))
        ctl_ttl = hdr[0]
        ctl = ctl_ttl >> 7
        seq = int.from_bytes(hdr[1:4], "big")
        src = int.from_bytes(hdr[4:6], "big")

        net_nonce = (b"\x00" + bytes([ctl_ttl]) + hdr[1:4] + hdr[4:6]
                     + b"\x00\x00" + self.iv_index.to_bytes(4, "big"))
        try:
            pt = MC.aes_ccm_decrypt(self.enc_key, net_nonce, net_ct,
                                    mic_len=8 if ctl else 4)
        except Exception:
            return None
        if len(pt) < 3:
            return None
        dst = int.from_bytes(pt[:2], "big")
        tp = pt[2:]

        out = {"src": src, "dst": dst, "seq": seq, "ctl": ctl,
               "transport": tp, "access": None, "opcode": None, "params": None,
               "akf": None, "aid": None}
        if ctl or len(tp) < 5:
            return out

        lt_hdr = tp[0]
        seg, akf, aid = (lt_hdr >> 7) & 1, (lt_hdr >> 6) & 1, lt_hdr & 0x3F
        if seg:
            return out
        up_ct = tp[1:]
        key = self.app_key if akf else self.dev_key
        if key is None:
            return out
        up_nonce = (bytes([0x01 if akf else 0x02, (ctl << 7) & 0x80]) + hdr[1:4]
                    + hdr[4:6] + pt[:2] + self.iv_index.to_bytes(4, "big"))
        try:
            access = MC.aes_ccm_decrypt(key, up_nonce, up_ct, 4)
        except Exception:
            return out
        out.update({"akf": akf, "aid": aid, "access": access,
                    "opcode": parse_opcode(access),
                    "params": access[opcode_len(access):]})
        return out


# =====================================================================
# Access 层 opcode 编解码
# =====================================================================

def encode_opcode(op: int) -> bytes:
    """把「惯例写法」的 opcode 编成真实字节。

    惯例写法（Mesh 规范文档与各家实现里通用）：
        0x00..0x7E         → 1 字节
        0x8000..0xBFFF     → 2 字节，首字节即 0x80..0xBF
        0xC00000..0xFFFFFF → 3 字节，首字节即 0xC0..0xFF
    所以 0x8008 就是两个字节 80 08（Config Composition Data Get），
    0xC00000|0x11C8F0 = 0xD1C8F0 → 三个字节 d1 c8 f0。
    """
    if op < 0x80:
        return bytes([op])
    if 0x8000 <= op <= 0xBFFF:
        return bytes([(op >> 8) & 0xFF, op & 0xFF])
    return bytes([(op >> 16) & 0xFF, (op >> 8) & 0xFF, op & 0xFF])


def opcode_len(access: Optional[bytes]) -> int:
    if not access:
        return 0
    b0 = access[0]
    return 1 if b0 < 0x80 else (2 if b0 < 0xC0 else 3)


def parse_opcode(access: Optional[bytes]) -> Optional[int]:
    """解析回「惯例写法」的 opcode 数值"""
    if not access:
        return None
    n = opcode_len(access)
    if len(access) < n:
        return None
    if n == 1:
        return access[0]
    if n == 2:
        return 0x8000 | (((access[0] & 0x3F) << 8) | access[1])
    return 0xC00000 | (((access[0] & 0x3F) << 16) | (access[1] << 8) | access[2])


# =====================================================================
# 自检
# =====================================================================

def self_test() -> bool:
    print("=" * 76)
    print(" mesh_net 自检")
    print("=" * 76)
    ok = True

    nid, enc, priv = k2(NET_KEY, 0x00)
    aid = k4(APP_KEY)
    print(f"  NID            = 0x{nid:02X}")
    print(f"  EncryptionKey  = {enc.hex()}")
    print(f"  PrivacyKey     = {priv.hex()}")
    print(f"  AID            = 0x{aid:02X}")
    print(f"  NetworkID(k3)  = {k3(NET_KEY).hex()}")

    checks = [
        ("EncKey 与 PrivKey 不同", enc != priv),
        ("k3 输出 8 字节", len(k3(NET_KEY)) == 8),
        ("NID 是 7 位", 0 <= nid < 128),
        ("AID 是 6 位", 0 <= aid < 64),
        ("k2/k3/k4 可重复", k2(NET_KEY) == (nid, enc, priv) and k4(APP_KEY) == aid),
    ]
    for name, good in checks:
        ok &= bool(good)
        print(f"    [{'OK ' if good else 'FAIL'}] {name}")

    for op in (0x02, 0x8008, 0x803D, 0x8049, 0xD1C8F0, 0xC00000):
        b = encode_opcode(op)
        good = parse_opcode(b) == op
        ok &= good
        print(f"    [{'OK ' if good else 'FAIL'}] opcode 0x{op:06X} ↔ {b.hex()}")

    # 组帧 → 解帧 往返
    node = MeshNode(dev_key=bytes(range(16)))
    for akf in (False, True):
        frame = node.build(NODE_ADDR, encode_opcode(OP_COMPOSITION_DATA_GET),
                           akf=akf, seq=0x000123)
        got = node.parse(frame)
        good = (got is not None and got["opcode"] == OP_COMPOSITION_DATA_GET
                and got["dst"] == NODE_ADDR and got["akf"] == int(akf)
                and got["seq"] == 0x000123
                and (got["aid"] == aid if akf else got["aid"] == 0))
        ok &= good
        print(f"    [{'OK ' if good else 'FAIL'}] 组帧/解帧往返 AKF={int(akf)} "
              f"（{len(frame)} 字节，opcode=0x{got['opcode']:04X}）"
              if got else f"    [FAIL] 组帧/解帧往返 AKF={int(akf)}")

    print("\n" + "-" * 76)
    print(" 结论:", "全部通过" if ok else "有失败项")
    print("=" * 76)
    return ok


def self_test_silent() -> bool:
    """静默自检：只校验密钥派生与 opcode 编解码的一致性，不打印。"""
    try:
        nid, enc, priv = k2(NET_KEY, 0x00)
        aid = k4(APP_KEY)
        if not (0 <= nid < 128 and 0 <= aid < 64 and enc != priv):
            return False
        if k2(NET_KEY) != (nid, enc, priv) or k4(APP_KEY) != aid:
            return False
        for op in (0x02, 0x8008, 0x8000, 0x803D, 0x8049, 0xD1C8F0):
            if parse_opcode(encode_opcode(op)) != op:
                return False
        node = MeshNode(dev_key=bytes(range(16)))
        for akf in (False, True):
            got = node.parse(node.build(NODE_ADDR, encode_opcode(OP_COMPOSITION_DATA_GET),
                                        akf=akf, seq=7))
            if got is None or got["opcode"] != OP_COMPOSITION_DATA_GET or got["seq"] != 7:
                return False
        return True
    except Exception:
        return False


if __name__ == "__main__":
    import sys
    sys.exit(0 if self_test() else 1)
