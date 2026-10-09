# 逆向结论全集：Nanlite Wand（Feasycom FeasyMesh）

本文只写**实测成立**的东西，并明确标出被推翻过的假设 —— 后者同样值钱，因为踩坑的顺序基本可复现。
凡是"推断"都写着"推断"，凡是"实测"都写着怎么测出来的。

---

## 1. 这条链路的分层

```
BLE 承载       PB-GATT / GATT Proxy（标准蓝牙 Mesh 的外壳）
  服务 0x1828：写 0x2ADD、通知 0x2ADE      ← Mesh 网络 PDU（不透明字节）
  服务 0x1827：写 0x2ADF、通知 0x2AE0      ← 仅配网阶段（PB-GATT）
  ★ 同一条连接上还有 0xFFF0：写 0xfff2 / 通知 0xfff1   ← Feasycom 私有通道
厂商 SDK 层    FeasyMesh（Feasycom 在标准 Mesh 之上加的私货：认证 + "快速命令"）
Mesh 网络层    NID 混淆 + AES-CCM + NetMIC（标准 SIG Mesh）
上层传输       未分段 ≤ 11B 载荷 / 分片 12B 一片（标准）
Access         厂商模型消息：opcode 3 字节 = 0xC0|(cmd&0x3F) ‖ CID 小端两字节
```

**Composition Data 实测**：CID `0x1111`、厂商 Model ID `0x11111111`、`NumVendors = 1`。
这和 App 字节码里硬编码的 `mModelIdentifier = 0x11111111 / mCompanyIdentifier = 0x1111` 完全吻合
（`com.nanlink.common.nancmd` / `FeasyMessageManger.sendVendorModelMessage`）。

---

## 2. 配网（PB-GATT）与密钥

标准 SIG Mesh 那一套都在：`k1`（会话密钥）、`k2`（NID / EncryptionKey / PrivacyKey）、
`k3`（NetworkID）、`k4`（AID）、AES-CCM、P-256 ECDH。要点：

- **`k1(N, SALT, P)` 里的 P 是 ASCII 标签**（`prdk`/`pkdk`/`ckdk`/`nksk` 等），不是序号。
  写错的话网络层能过、Access 层解不开，表现成"灯收到但毫无反应"。
- **DeviceKey 每次配网都不同**（由本次 ECDH 秘密推导）。必须落盘；
  复用旧的 DeviceKey → Config 消息全部静默失败。
- **本项目配网时现场生成随机 NetKey/AppKey**，不复用别人的网络参数 —— 复现的是流程，不是密钥。

⚠️ 一条走过死路的推断：**想从第三方网络的抓包里"反推"会话密钥**。ECDH 私钥从不上空口，
抓包只有公钥；靠公开数据 + 猜盐去恢复会话密钥是不可行的，别在这上面花时间。
（要用自己的网络做实验，就自己配网、自己抓。）

---

## 3. ★ Feasycom TEA 认证（两周卡点的真身）

灯会**照常解密并回显**你的 Mesh 厂商帧，但**不认证就绝不驱动光**。认证与 Mesh 无关，
走同一条 BLE 连接上的 `0xFFF0`：

```
写 0xfff2 / 通知 0xfff1
挑战 = 4 随机字节 + 4 个 0x00                     （8 字节）
包   = "AUTH" ‖ TEA(挑战, rounds) ‖ TEA(挑战, rounds)     = 4 + 8 + 8 = 20 字节
轮数依次试 32 → 2 → 1，哪一轮灯答话就用哪一轮（Wand 实测 rounds=32）
TEA：标准算法，8 字节块 = 大端两个 uint32，DELTA=0x9E3779B9，MASK=0xFFFFFFFF
```

TEA 密钥（16 字节）出自 NANLINK APK 自带的原生库：

```
Nanlink_*.apk → lib/{arm64-v8a, armeabi-v7a}/libencrypted.so
在符号字符串 "getRandomNumber\0" 之后的 16 字节，两个架构取值一致
同库导出 random_number_encrypt / create_random_number /
        EncryptAlgorithm$Universal_randomNumberMatches   ← 与"随机数匹配式认证"吻合
```

自己复核（不用信本文给的常数）：

```bash
unzip -o Nanlink_*.apk 'lib/*/libencrypted.so'
strings -a lib/arm64-v8a/libencrypted.so | grep -n -A2 getRandomNumber
# 或用 r2：/x getRandomNumber\0  之后读 16 字节
```

认证之后同一通道还有 ASCII 诊断命令（`\r\n` 结尾，APK 里只存在这两条）：

| 命令 | 应答 | 用途 |
| --- | --- | --- |
| `$FSCCMD001$` | `$001-XXXX$` | **设备的 Mesh 单播地址**（十六进制）—— 拿它当控制目标，别猜 |
| `$FSCCMD002$` | `$002-XHHHHHHHH$` | IV 更新标志 + IV Index（Wand 实测**无应答**，不影响控灯） |

未配网的设备上 `$FSCCMD001$` 会返回 `$001-0000$`。

---

## 4. 命令码：`C1` 是命令，`C2` 是状态

厂商 opcode = `0xC0|(cmd&0x3F)` ‖ `CID 低字节` ‖ `CID 高字节` → `C1 11 11` / `C2 11 11`。

- **驱动光的命令是 `C1 11 11`。**
- `C2 11 11` 是状态/应答码。历史上把 `C2` 当命令码，是因为照抄了 JSON 模板里
  `FLM_CCT` 的字段值 `0x02` 当 opcode 低字节（`0xC0|0x02 = 0xC2`）—— 一个看起来极合理的错。
- 用 `C2` 发命令时灯**也会回显**，所以"有回显"从来不是生效的证据。

---

## 5. 载荷：快速命令（生效的那个）

APK 的 `NanCmd` 里有三个构造器：`fastCommand` / `fullCmd` / `longFastCmd`。
**实测驱动 Wand 的是 8 字节 fastCommand**：

```
[0]   rollCode      防重放递增计数（固定值会被丢）
[1]   functionCode  bit5 = 操作（1 SET / 0 QUERY）；bit0 = needReturn（1 要求回话）
[2]   typeCode      灯控恒 0x01
[3]   optionCode    见下表
[4:6] value         uint16 大端
[6:8] channel       uint16 大端，单播填 0
```

| option | 含义 | 标尺 | 实测 |
| --- | --- | --- | --- |
| `0x01` | 亮度 | **0–100 直值** | ✅ 30/40/65/85/100/5 全按值生效 |
| `0x03` | 色温 | **开尔文直值** | ✅ 2700/2900/3300/5600 |
| `0x04` | 绿/品 | **0–100，50 = 中性** | ✅ 断电重开仍 50，与出厂默认一致 |
| `0x05` | 色相 | tint 模式下 0–360 | ❌ 被解析、被 ACK，光不变 |
| `0x0C` | 饱和 | tint 模式下 0–100 | ❌ 同上 |

**没有 ×655.35、没有 `|0x8000`、没有"首字节是长度"** —— 这三条都是历史上真实犯过的错。

### fullCmd（别的机型吃它，Wand 不吃）

老协议的 11 字节色温 / 8 字节彩色载荷，首字节 = 长度（老资料里叫 `ssize`）：

```
CCT: 0B | DIM(2) | 02 | 02 | OUTPUT_MODE | CCT(2) | GM(2) | SOURCE_MODE
HSI: 08 | DIM(2) | 03 | 01 | HUE(2) | SAT(1)
```

其中 `DIM` 确实是 0–65535 标尺（历史锚点：`0x0ccd` = 5%）。
**但这套在 Wand 上实测 0 回包、0 生效**（`C1`/`C2` 都试过；`tools/opcode_scan.py`
把 `C0..CF` 全扫了一遍，16 个 opcode 全沉默，而同轮前后各一条已知生效的快速命令
分别回了 2 条应答 —— 阳性对照成立，所以是结构不被接受，不是发不出去）。

---

## 6. 判据学：什么算"灯收到了"，什么算"灯生效了"

这一节是整个项目最贵的部分，因为它决定你后面会不会在错的方向上耗两周。

| 现象 | 能证明 | 不能证明 |
| --- | --- | --- |
| Mesh 帧被灯解密并**回显** | 密钥对、网络通、送达 | 光会动 |
| 快速命令的**那帧固定 ACK**（`01 22 02 01 0000 0000`） | 这是一条格式正确且置了 needReturn 的快速命令 | **option 有效**、参数值、状态 |
| Config 消息的**状态码 `0x00`** | 那一步在 Config 层成功（AppKey Add / Model App Bind） | 光会动 |
| 灯屏幕数字变化 | 该参数被接受并显示 | —（但注意：灯**断电重开会落回出厂默认**，所以"自己变了"不算证据） |
| **肉眼看到光变了** | 生效 | — |

血泪教训两条：

1. 把"有 ACK"当参数有效性判据，去扫 `option 0x00..0x2F` → **48 个全部有 ACK，0 个被拒**，
   整轮结论作废。**唯一判据是肉眼看到光变了。**
2. **扫参就是写参**。那次扫描用非中性值（120）遍历 option，把 `0x04/0x05/0x0C` 真写进了灯的
   非易失寄存器，事后表现为灯上"红绿"读数变 120、且手机每调一次就拿存值重画。
   ⇒ 任何遍历参数的实验**必须自带复位脚本**（见 `tools/tint_reset.py`）。

---

## 7. 重放保护：SEQ 与 rollCode

- Mesh SEQ 必须严格递增，重复/回退的 SEQ 被**静默丢弃**（没有任何错误回执）。所以要持久化，
  并且**一台灯只能有一份**：两份代码各自维护 SEQ 会互相把对方的消息当重放丢掉。
- 快速命令另有 rollCode（8 位，递增）。固定值会被丢。
- 本项目两者都存在 `$NANLITE_DATA_DIR`（`seq.txt` / `roll.txt`）。

---

## 8. 时序与延迟

实测（桥内自己打点，`nanlite-wand serve` 每次改动会写一行分解）：

```
时延：MQTT→唤醒 2ms + 去抖 101ms + 节流 0ms + 下发 64ms = 167ms（桥内合计）
```

可压的是去抖（合并滑块连发）、指令间隔、每条 60ms 的发送间隔；
**下限不在软件手里**：BLE 连接间隔 + Feasycom 把帧从 GATT 转进 Mesh 的那一跳。
另外灯的渐变本身很慢，"下发完"和"看到变化"之间有物理延迟。

---

## 9. 结论演进（留档，免得重复犯错）

| 曾经的结论 | 现状 |
| --- | --- |
| 首字节是载荷长度（`ssize`） | ❌ 快速命令里是 rollCode；"长度"只对 fullCmd 成立 |
| `C2 11 11` 是命令码 | ❌ 是状态/应答码 |
| 亮度要 `×65535/100` 或 `|0x8000` | ❌ 快速命令是 0–100 直值 |
| 存在第二条控制通道（`A5A5` 开头的帧） | ❌ 那是**另一台设备**的 OTA（按 ACL 句柄归属判定的） |
| 抓包里的载荷是 CBOR | ❌ 假阳性：解析器允许尾随垃圾，706 条里 0 条完整 |
| "灯能回显说明命令基本对了" | ❌ 回显只证明送达 |
| 一帧历史 fullCmd 曾肉眼生效（5%） | ❌ 复现不了，不作证据 |
| TEA 认证 + `C1` + 8 字节快速命令 + rollCode | ✅ 现行结论，已跑通 HomeKit 全链路 |

## 10. 怎么自己验证（不依赖本文）

```bash
nanlite-wand selftest          # CMAC 标准向量 + CCM 往返 + 命令字节夹具
python3 tests/test_bytes.py    # 帧长 30B、自造自解、option 标尺
nanlite-wand listen --seconds 60   # 灯会不会主动推（结论：不会）
python3 tools/opcode_scan.py   # 阳性对照 + opcode 扫描（要挂"维护锁"独占连接）
python3 tools/option_scan.py   # option 空间与 ACK 语义
```
