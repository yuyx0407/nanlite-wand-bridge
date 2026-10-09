#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crypto.py —— SIG Mesh 密码学原语（配网阶段所需）
====================================================

对应 Mesh Profile 1.0 §3.8.2（密钥派生）与 §5.4.2（配网密码学）。

只用标准原语，全部来自 cryptography 库，自己实现的只是规范规定的组合方式：
    s1(M)  = AES-CMAC(SALT, M)              SALT = 16 字节 0x00
    k1(S,P)= AES-CMAC(S, P)
    ECDH   = P-256，共享密钥取 X 坐标 32 字节大端

自带自检：用 RFC 4493 的 AES-CMAC 标准向量验证底层实现正确，
再验证 s1/k1 的输入输出长度与确定性。**自检不过就不要往下走。**
"""

from __future__ import annotations

import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms

# ---------------------------------------------------------------------------
# 基础：AES-CMAC
# ---------------------------------------------------------------------------

# Mesh Profile 3.8.2.1 定义的 SALT = 16 个 0x00
SALT = bytes(16)


def aes_cmac(key: bytes, msg: bytes) -> bytes:
    """AES-CMAC(key, msg) → 16 字节"""
    c = CMAC(algorithms.AES(key))
    c.update(msg)
    return c.finalize()


def s1(m: bytes) -> bytes:
    """s1(M) = AES-CMAC(ZERO, M)，ZERO = 16 字节 0x00

    官方文档原话：k is always set to the 128-bit value 0x0000…0000,
    which is referred to as ZERO in the specification。
    """
    return aes_cmac(SALT, m)


def k1(n: bytes, salt: bytes, p: bytes) -> bytes:
    """k1(N, SALT, P) = AES-CMAC( AES-CMAC(SALT, N), P )

    ★ 这是 Mesh 规范里最容易写错的一个函数：它是**双重 CMAC**，
      而且第三个参数 P 是一个**ASCII 字符串标签**，不是数值。
      配网里用到的三个 P：
          b"prck" → Provisioning Confirmation Key
          b"prsk" → Provisioning Session Key
          b"prsn" → Provisioning Session Nonce
    （一开始我只做了一次 CMAC、也没加 P 标签，导致设备一直判定
      Confirmation 校验失败并直接断开连接。）
    """
    t = aes_cmac(salt, n)          # 内层：key = SALT, msg = N
    return aes_cmac(t, p)          # 外层：key = 内层结果, msg = P 字符串


def k2(n: bytes, p: bytes) -> bytes:
    """k2(N, P) = AES-CMAC( AES-CMAC(SALT, N), 0x02 || P )"""
    t = aes_cmac(SALT, n)
    return aes_cmac(t, b"\x02" + p)


def k3(n: bytes) -> bytes:
    """k3(N) = AES-CMAC( AES-CMAC(SALT, N), 0x03 )"""
    t = aes_cmac(SALT, n)
    return aes_cmac(t, b"\x03")


def k4(n: bytes) -> bytes:
    """k4(N) = AES-CMAC( AES-CMAC(SALT, N), 0x04 )"""
    t = aes_cmac(SALT, n)
    return aes_cmac(t, b"\x04")


# ---------------------------------------------------------------------------
# AES-CCM（Mesh 用 8 字节 MIC；nonce 13 字节）
# ---------------------------------------------------------------------------

def aes_ccm_encrypt(key: bytes, nonce: bytes, msg: bytes, mic_len: int = 8) -> bytes:
    """返回 密文 || MIC"""
    return AESCCM(key, tag_length=mic_len).encrypt(nonce, msg, None)


def aes_ccm_decrypt(key: bytes, nonce: bytes, ct: bytes, mic_len: int = 8) -> bytes:
    """输入 密文 || MIC，返回明文；校验失败抛异常"""
    return AESCCM(key, tag_length=mic_len).decrypt(nonce, ct, None)


# ---------------------------------------------------------------------------
# P-256 ECDH
# ---------------------------------------------------------------------------

def gen_p256_keypair() -> Tuple[bytes, ec.EllipticCurvePrivateKey]:
    """生成 P-256 密钥对，返回 (公钥 XY 64 字节大端, 私钥对象)"""
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    xy = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    return xy, priv


def ecdh_shared_secret(priv: ec.EllipticCurvePrivateKey, peer_xy: bytes) -> bytes:
    """用私钥和对方公钥 XY(64字节) 算出共享密钥，取 X 坐标 32 字节大端。

    注意：Mesh 规范要求用 RFC 6090 的 ECDH，共享密钥 = 共享点的 X 坐标。
    cryptography 的 exchange() 返回的正是 X 坐标（32 字节）。
    """
    if len(peer_xy) != 64:
        raise ValueError(f"对端公钥应为 64 字节，收到 {len(peer_xy)}")
    x = int.from_bytes(peer_xy[:32], "big")
    y = int.from_bytes(peer_xy[32:], "big")
    peer_pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    return priv.exchange(ec.ECDH(), peer_pub)


# ---------------------------------------------------------------------------
# 配网阶段的密钥派生（Mesh Profile 5.4.2.4 / 5.4.2.5）
# ---------------------------------------------------------------------------

def confirmation_salt(confirmation_inputs: bytes) -> bytes:
    """ConfirmationSalt = s1(ConfirmationInputs)"""
    return s1(confirmation_inputs)


def confirmation_key(conf_salt: bytes, ecdh_secret: bytes) -> bytes:
    """ConfirmationKey = k1(ECDHSecret, ConfirmationSalt, "prck")"""
    return k1(ecdh_secret, conf_salt, b"prck")


def confirmation_value(conf_key: bytes, random_: bytes, auth_value: bytes) -> bytes:
    """Confirmation = AES-CMAC(ConfirmationKey, Random || AuthValue)

    No OOB 时 AuthValue = 16 字节 0x00。
    """
    if len(random_) != 16 or len(auth_value) != 16:
        raise ValueError("Random / AuthValue 都必须是 16 字节")
    return aes_cmac(conf_key, random_ + auth_value)


def provisioning_salt(conf_salt: bytes, prov_random: bytes, dev_random: bytes,
                      variant: int = 1) -> bytes:
    """ProvisioningSalt 的几种可能构造（规范是 v1）：

        v1: s1(ConfirmationSalt || ProvisionerRandom || DeviceRandom)   ← 规范
        v2: s1(ConfirmationSalt || DeviceRandom || ProvisionerRandom)   ← 两个随机数对调
        v3: s1(ProvisionerRandom || DeviceRandom)                       ← 不含 ConfirmationSalt
        v4: s1(DeviceRandom || ProvisionerRandom)
    """
    if variant == 1:
        return s1(conf_salt + prov_random + dev_random)
    if variant == 2:
        return s1(conf_salt + dev_random + prov_random)
    if variant == 3:
        return s1(prov_random + dev_random)
    return s1(dev_random + prov_random)


def session_key(prov_salt: bytes, ecdh_secret: bytes) -> bytes:
    """SessionKey = k1(ECDHSecret, ProvisioningSalt, "prsk")"""
    return k1(ecdh_secret, prov_salt, b"prsk")


def session_nonce(prov_salt: bytes, ecdh_secret: bytes,
                  prov_random: bytes, dev_random: bytes, variant: int = 2) -> bytes:
    """SessionNonce = k1(ECDHSecret, ProvisioningSalt, "prsn") 的**后 13 字节**

    ★★ 这是配网里"最后一公里"的坑，直接导致设备回 `Provisioning Failed
      —— Decryption Failed`（错误码 0x06）。

      Mesh Profile 5.4.2.4 写的是"取 k1 输出的 **13 个最低有效字节**"，
      即 16 字节输出的**下标 3..15**，而不是前 13 个字节。
      参考实现（南光 App 用的 FeasyMesh 库）字节码逐条印证：

          ProvisioningDataState->a([B [B)
            sget-object v0, SecureUtils->PRSN
            invoke-static v3, v4, v0, SecureUtils->calculateK1([B [B [B)[B
            move-result-object v3           ; v3 = k1(...) 16 字节
            array-length v4, v3             ; v4 = 16
            const/4 v0, 3
            sub-int/2addr v4, v0            ; v4 = 13
            invoke-static v4, ByteBuffer->allocate(I)      ; 分配 13 字节
            invoke-virtual v4, v3, v0, v1, ByteBuffer->put([B I I)   ; 从下标 3 起拷 13 字节

      我先前写成 [:13]，nonce 一错 AES-CCM 必然解不开，症状完全对得上。

    variant=2 → [3:16]（规范正确值，默认）
    variant=1 → [:13]（错误写法，保留仅为对照排查）
    """
    full = k1(ecdh_secret, prov_salt, b"prsn")
    return full[3:16] if variant == 2 else full[:13]


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def self_test_quick() -> bool:
    """静默版自检：只跑 RFC 4493 标准向量，返回是否通过。供配网器启动时调用。"""
    K = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    cases = [
        (bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
         "070a16b46b4d4144f79bdd9dd04a287c"),
        (bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                       "ae2d8a571e03ac9c9eb76fac45af8e51"
                       "30c81c46a35ce411"),
         "dfa66747de9ae63030ca32611497c827"),
    ]
    for msg, want in cases:
        if aes_cmac(K, msg).hex() != want:
            return False
    # AES-CCM 往返
    pt = bytes(range(24))
    ct = aes_ccm_encrypt(bytes(16), bytes(13), pt)
    return aes_ccm_decrypt(bytes(16), bytes(13), ct) == pt


def self_test() -> bool:
    ok = True
    print("=" * 72)
    print(" mesh_crypto 自检")
    print("=" * 72)

    # --- RFC 4493 AES-CMAC 标准向量 ---
    K = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    vectors = [
        (bytes(0), "bb1d6929e95937287fa37d129b756746"),
        (bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
         "070a16b46b4d4144f79bdd9dd04a287c"),
        (bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                       "ae2d8a571e03ac9c9eb76fac45af8e51"
                       "30c81c46a35ce411"),
         "dfa66747de9ae63030ca32611497c827"),
        (bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                       "ae2d8a571e03ac9c9eb76fac45af8e51"
                       "30c81c46a35ce411e5fbc1191a0a52ef"
                       "f69f2445df4f9b17ad2b417be66c3710"),
         "51f0bebf7e3b9d92fc49741779363cfe"),
    ]
    print("\n  RFC 4493 AES-CMAC 标准向量：")
    for msg, want in vectors:
        got = aes_cmac(K, msg).hex()
        same = got == want
        ok &= same
        print(f"    [{'OK ' if same else 'FAIL'}] {len(msg):>2} 字节输入 → {got}")
        if not same:
            print(f"           期望 {want}")

    # --- 长度与确定性检查 ---
    print("\n  组合函数检查：")
    salt = s1(b"test")
    ok &= (len(salt) == 16)
    print(f"    [{'OK ' if len(salt)==16 else 'FAIL'}] s1() 输出 16 字节")
    for f, name in ((s1, "s1"),):
        a, b = f(b"abc"), f(b"abc")
        same = a == b
        ok &= same
        print(f"    [{'OK ' if same else 'FAIL'}] {name}() 确定性")

    # --- AES-CCM 往返 ---
    key = bytes(range(16))
    nonce = bytes(range(13))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff0102030405060708")
    ct = aes_ccm_encrypt(key, nonce, pt)
    ok &= (len(ct) == len(pt) + 8)
    back = aes_ccm_decrypt(key, nonce, ct)
    same = back == pt
    ok &= same
    print(f"    [{'OK ' if same else 'FAIL'}] AES-CCM 往返（明文 {len(pt)} → 密文+MIC {len(ct)}）")

    # --- P-256 ECDH 双向往返（两端算出同一个共享密钥）---
    xy_a, priv_a = gen_p256_keypair()
    xy_b, priv_b = gen_p256_keypair()
    sa = ecdh_shared_secret(priv_a, xy_b)
    sb = ecdh_shared_secret(priv_b, xy_a)
    same = (sa == sb) and len(sa) == 32
    ok &= same
    print(f"    [{'OK ' if same else 'FAIL'}] P-256 ECDH 双方算出的共享密钥一致（32 字节）")
    print(f"          共享密钥示例: {sa.hex()[:32]}…")

    print("\n" + "-" * 72)
    print(" 结论:", "全部通过 —— 密码学底座可用" if ok else "存在失败项，不要往下走")
    print("=" * 72)
    return ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if self_test() else 1)
