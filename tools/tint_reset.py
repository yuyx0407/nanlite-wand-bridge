#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tint_reset.py —— 把被扫参留下的色调/色相/饱和寄存器清回中性

起因：option_scan.py 拿值 120 扫了 option 0x00..0x2F，灯的快速命令解析器**照单全收**
（ACK 判据也证实了"全 48 个都认"），于是 0x04 绿/品、0x05 色相、0x0C 饱和被留在了
非中性值上，表现为灯上「红绿」读数变 120，且每次手机调亮度/色温后重新显示出来。

走桥的 set/raw 注入通道（不抢 BLE 连接），rollCode 用 fast_cmd 的同一份持久计数。

跑法：python3 tint_reset.py
"""
import subprocess
import time

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nanlite_wand import commands as FC

TOPIC_RAW = os.environ.get("NANLITE_TOPIC_PREFIX", "nanlite/wand") + "/set/raw"
TOPIC_CCT = os.environ.get("NANLITE_TOPIC_PREFIX", "nanlite/wand") + "/set/colorTemperature"
M = os.environ.get("MOSQUITTO_PUB", "mosquitto_pub")

# option → 清成什么值（绿/品按"线上值=用户值+50"，所以 50 才是居中 0）
CLEAR = [
    (FC.OPT_GM, 50, "绿/品 → 居中(用户 0)"),
    (FC.OPT_HUE, 0, "色相 → 0"),
    (FC.OPT_SAT, 0, "饱和 → 0（tint 分量彻底归零）"),
    (0x02, 0, "option 0x02（动画参数）→ 0"),
    (0x00, 0, "option 0x00 → 0"),
]


def main():
    for option, value, what in CLEAR:
        pdu_hex = FC.fast_cmd(option, value, FC.SET).hex()
        subprocess.run([M, "-h", "127.0.0.1", "-p", "1883",
                        TOPIC_RAW,
                        "-m", f"01:{pdu_hex}"], check=True)
        print(f"  已发：{what}   载荷={pdu_hex}", flush=True)
        # 桥的 set/raw 每条要占住主循环 14 秒（等回包窗口），期间来第二条会互相覆盖，
        # 所以必须串行等干净，不能连发。
        time.sleep(16.0)

    # 收尾把亮度/色温按手机侧现值重发一次，别留在扫描时的怪值上
    subprocess.run([M, "-h", "127.0.0.1", "-p", "1883",
                    TOPIC_CCT, "-m", "303"], check=True)
    print("\n完成。现在请在灯上看：「红绿」读数应回到 0/居中；"
          "再用手机调一次亮度或色温，如果它仍是 0，就说明寄存器真的清掉了。", flush=True)


if __name__ == "__main__":
    main()
