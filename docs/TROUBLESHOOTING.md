# 排障（按症状索引）

先记住两条判据，能省掉一半的弯路：

- **灯会回显 / 会 ACK ≠ 命令生效**。唯一判据是肉眼看到光变了。
- **Config 消息有状态码（`0x00` = 成功）**，所以"装钥匙"这类步骤是可验证的；
  厂商控制命令基本没有可信回执，只能靠现象。

---

## A. 扫不到 / 连不上灯

| 检查 | 怎么办 |
| --- | --- |
| 灯的 BLE **只接受一条连接** | 关掉 NANLINK App（要杀后台，不只是退出界面）；或先让灯断电重插 |
| 灯没通电 | 通电后它才会广播 Mesh Proxy `0x1828` / 未配网时广播 `0x1827` |
| macOS 没给蓝牙权限 | 碰蓝牙的进程必须有 `NSBluetoothAlwaysUsageDescription`，否则直接 SIGABRT（退出码 134）。用 `./deploy/install-macos.sh` 生成的 `.app` 包装跑 |
| 名字不匹配 | 别的型号用 `--target <广播名前缀>` 或 `--address <BD_ADDR>` 跳过扫描 |

```bash
nanlite-wand scan --target P24002
```

## B. 连上了、认证过了，但光不动

按这个顺序排查，每步都有可观测证据：

1. **TEA 认证是否真的通过**（日志要有 `✅ 认证通过（rounds=…）`）。
   没认证时灯**照样解密并回显**厂商帧 —— 这是最容易骗过人的地方。
   失败就先给灯断电重插再连；仍失败说明 TEA 密钥/轮数不对（`docs/PROTOCOL.md` 第 3 节有自抽方法）。
2. **命令码必须是 `C1 11 11`**。用 `C2` 也会看到回显，但不驱动光。
3. **控制目标地址**：`$FSCCMD001$` 会返回灯的真实单播地址（`$001-XXXX$`）。
   未配网时返回 `$001-0000$`。地址不对就打不到。
4. **SEQ 被当重放丢掉**：SEQ 必须严格递增且**一台灯只有一份**。
   如果你同时跑了两份代码（比如现场一套 + 仓库一套），它们的 `seq.txt` 会互相拖后腿。
   → 让两边共用同一个 `$NANLITE_DATA_DIR`，或只留一份在跑。
5. **rollCode 固定值**：递增计数被写死时灯可能直接丢。
6. **AppKey 没装上/没绑模型**：跑 `nanlite-wand bind`，看 `AppKey Add` 与 `Model App Bind`
   的状态码是不是 `0x00`。

## C. 配网失败 / 配完控制不了

- `Config AppKey Add` 的 opcode 是**单字节 `0x0000`**，`Delete` 才是 `0x8000`（资料常写反）。
- `Model App Bind` 参数是**小端**打包：元素地址(LE) ‖ AppKeyIndex(2 字节顺序调换) ‖ CID(LE) ‖ ModelID(LE)。
- **DeviceKey 每次配网都不同**（本次 ECDH 推导）。没落盘就复用旧值 → 网络层能过、Access 层解不开，
  表现成"能连上但灯毫无反应"。
- `k1(N, SALT, P)` 的 P 是 ASCII 标签（`prdk`/`pkdk`/`ckdk`/`nksk`），不是序号。

## D. HomeKit 搜不到桥 / 添加时一直转圈

见 `docs/HOMEKIT.md` 第 4、5 节。两条最常见：

- **通告发到了别的网口** → `bridge.bind` 指定接口名（注意 `bridge.interfaces` 在 Homebridge 2.4 已失效）。
- **`sf=0`**（在 Home App 里删配件不会通知 Homebridge）→ 把 `persist/AccessoryInfo.*.json`
  和 `IdentifierCache.*.json` 挪走再重启，`dns-sd -L` 里要看到 `sf=1`。

本机验收（不用碰手机）：

```bash
python3 -c "import socket;print(socket.if_nameindex())"
dns-sd -B _hap._tcp local          # 要看到你选的那个接口 index
dns-sd -G v4 <实例名>.local        # 地址 = 该接口的 IP
```

⚠️ 自己绑 `5353 + SO_REUSEPORT` 抓 mDNS 的探针**不可信**：macOS 会把包分给 mDNSResponder，
本机自己发的多播也不回投给自己。**收不到 ≠ 线上没有**。只信 `dns-sd` / tcpdump。

## E. 时延高

看桥打的这一行，别看手感：

```
时延：MQTT→唤醒 2ms + 去抖 101ms + 节流 0ms + 下发 64ms = 167ms（桥内合计）
```

- 去抖/节流/发送间隔三个键见 `README.md` 的配置表；开/关点击已经跳过去抖。
- 若"节流"很大：说明指令间隔被上一条拖住，检查是不是有连发的 set 主题（mqttthing 的
  `confirmationPeriodms` 会重发同一条命令）。
- 若"下发"很大：BLE 连接间隔或 Feasycom 转 Mesh 的那一跳，软件压不动。

## F. 把灯写脏了（扫参后遗症）

用非中性值遍历 option 会**真的写进寄存器**（不驱动光 ≠ 不存值）。复位：

```bash
python3 tools/tint_reset.py      # 绿/品→50(中性)、色相/饱和→0、0x02/0x00→0
```

注意桥的 `set/raw` 每条要占住主循环 14 秒等回包，**连发会互相覆盖**，脚本里必须串行等待。
断电重开会回到出厂默认（这是最省事的兜底），但注意：正因为如此，
**"灯自己变了"不能作为任何命令生效的证据**。

## G. 想换别的 Nanlite 机型

90% 只用改两处：

- `commands.py` 的 option / 标尺 / 能力矩阵；
- `--target` 广播名前缀（以及必要时 Composition Data 里的 CID/Model ID）。

老机型（PavoTube / FC 系列）吃 `fullCmd`，`stack.cct_payload()/hsi_payload()` 保留了那种写法。
移植时先跑 `tools/opcode_scan.py`（带阳性对照）确认命令码，再跑 `tools/option_scan.py` 看参数空间。
