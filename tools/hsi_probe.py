#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hsi_probe.py —— 彩色模式到底怎么进：4 步高对比对照

背景：快速命令 8B `[roll,func,type,option,val,ch]` 里没有"模式"这一维，
option 0x05/0x0C 是从别人的 FS-300B 推断来的、参考仓库自己标注未实测。
而 APK 的 `flmModeList` 明确给出南光彩色模式走 **fullCmd**，载荷第 3 字节是模式：
    彩色 inner = SEQUENCE(1) DIM(2) FLM=03(1) SLM=01(1) HUE(2) SAT(1)   → 8 字节
    色温 inner = SEQUENCE(1) DIM(2) FLM=02(1) SLM=02(1) OUTMODE(1) CCT(2) GM(2) SRCCODE(1) → 11 字节

不发蓝牙（灯的 BLE 只接受一条连接，桥正占着），全部走桥的 `set/raw` 注入通道。
每步约 18s（raw 路径要等 14s 收应答）。灯只要动了，就报"第几步、变成什么"。
"""
import os
import os
import subprocess
import time

M = "/opt/homebrew/bin/mosquitto_pub"
LOG = os.path.expanduser("$NANLITE_DATA_DIR/bridge.log")
ROLL_FILE = os.path.join(os.environ.get(
    "NANLITE_DATA_DIR", os.path.expanduser("~/.local/share/nanlite-wand")), "roll.txt")


def roll_next(step: int = 3) -> int:
    try:
        v = int(open(ROLL_FILE).read().strip())
    except Exception:
        v = 0x40
    v = (v + step) & 0xFF
    with open(ROLL_FILE, "w") as f:
        f.write(str(v))
    return v


def pub(payload: str) -> None:
    subprocess.run([M, "-h", "127.0.0.1", "-p", "1883",
                    "-t", "nanlite/wand/set/raw", "-m", payload], check=True)


def run(idx: int, title: str, frame: str, expect: str, secs: int = 18) -> None:
    before = sum(1 for _ in open(LOG, errors="ignore"))
    print(f"\n=== 第 {idx} 步 · {title}\n    注入 {frame}\n    期望看到：{expect}"
          f"（{secs}s 内请只盯灯，别碰旋钮）", flush=True)
    pub(frame)
    time.sleep(secs)
    with open(LOG, errors="ignore") as f:
        for line in f.readlines()[before:]:
            if any(k in line for k in ("原始帧下发", "灯回包", "无回包", "下发失败")):
                print("   ", line.strip(), flush=True)


def main() -> None:
    # ★ 标尺（这次核过）：fullCmd 的 DIM 是 16 位 0–65535，不是 0–100。
    #   历史那帧 5% ↔ 0x0ccd(3277)，3277/65535 = 5.0% ⇒ pct×655.35。
    #   上一版探针按 0–100 填了 0x0032/0x0064 = 0.08%/0.15%，等于把灯设成熄灭，整轮不可判读。
    DIM_FULL = 0xFFFF            # 100%
    DIM_HALF = 0x8000            # 50%
    HUE_SCALED = 0x5555          # 120° × 65535/360
    HUE_240 = 0xAAAA             # 240° × 65535/360
    SAT_FULL = 0x64              # JSON 模板里 SAT 是 1 字节、用户值 100

    print("南光 Wand 彩色模式对照探针 v2（4 步，每步 18s，约 75s）"
          "\n每一步期望的样子都不同，请只盯灯，记下第几步动了、变成什么", flush=True)

    # 四级台阶：每步的期望互不相同，才分得清是哪一条生效
    # 1) C1 + 色温 fullCmd → 50% 冷白
    run(1, "C1 + 色温 fullCmd（50% / 5600K）",
        f"01:0b{DIM_HALF:04x}02020115e0000001", "50% 亮度的**冷白**光")

    # 2) C2 + 色温 fullCmd → 100% 暖白（和历史帧同 opcode，但值明显不同）
    run(2, "C2 + 色温 fullCmd（100% / 2700K）",
        f"02:0b{DIM_FULL:04x}0202010a86000001", "100% 亮度的**暖白**光")

    # 3) C2 + 彩色 fullCmd，色相 120° 按 0–65535 标尺 → 绿
    run(3, "C2 + 彩色 fullCmd（100% / 色相120°按16位标尺 / 饱和100）",
        f"02:08{DIM_FULL:04x}0301{HUE_SCALED:04x}{SAT_FULL:02x}", "100% 亮度的**纯绿**光")

    # 4) C1 + 彩色 fullCmd，色相 240° → 蓝（与第 3 步不同色，才能各归各的账）
    run(4, "C1 + 彩色 fullCmd（100% / 色相240°按16位标尺 / 饱和100）",
        f"01:08{DIM_FULL:04x}0301{HUE_240:04x}{SAT_FULL:02x}", "100% 亮度的**纯蓝**光")

    print("\n判读："
          "\n  绿/蓝都出来了 → 彩色走 fullCmd，顺手告诉我第 1/2 步有没有动（定 opcode）；"
          "\n  变的是红/橙而不是绿/蓝 → fullCmd 认，但色相标尺是 0–360 直值，我改一个字节就行；"
          "\n  只有 1/2 动、3/4 不动 → 色温 fullCmd 有效，彩色另有前置（SLM/通道）；"
          "\n  四步全不动 → fullCmd 整条不认（连历史那帧也不算数），回头扫快速命令的 option。",
          flush=True)


if __name__ == "__main__":
    main()
