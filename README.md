# nanlite-wand-bridge

把 **Nanlite Wand**（P24002，走 Bluetooth SIG Mesh / Feasycom FeasyMesh 方案）这类只能用手机 App
控制的灯具，接到你自己的控制器上：**电脑直接控**、**MQTT**、**HomeKit / Siri**，
以及给**独立硬件桥**（ESP32 等）预留好的传输层接口。

> English (TL;DR): Many Nanlite lights are Bluetooth-Mesh devices with a **proprietary Feasycom
> authentication layer on top**. They ignore standard Mesh application messages unless that layer
> is satisfied first. This project documents the whole chain (provisioning → key derivation →
> TEA auth → vendor "fast command") and ships a working bridge: `BLE Mesh ⇄ MQTT ⇄ HomeKit`,
> with the transport behind a small interface so a standalone hardware bridge can replace it.
> Verified on macOS with a Nanlite Wand; other FeasyMesh Nanlite models very likely share the
> protocol (see `docs/PROTOCOL.md`).

**它解决的具体问题**：这类灯"能连上、能配网、Mesh 层一切正常、厂商帧甚至会被解密回显"，
但**光不动**。卡在这里的人往往反复换 opcode、换载荷、换密钥 —— 真因是每次连接都必须先做的
私有 TEA 认证（`docs/PROTOCOL.md` 第 3 节），加上正确的命令码 `C1 11 11`。

---

## 现在能做到什么（能力矩阵，全部肉眼实测）

| 功能 | 状态 | 说明 |
| --- | --- | --- |
| 扫描 / 配网（PB-GATT） | ✅ | 自建 Mesh 网络，**密钥现场随机生成**，不复用任何人的 |
| DeviceKey / AppKey 推导与安装 | ✅ | 含 Config 层回执验证（AppKey Status、Model App Status） |
| 亮度 | ✅ | option `0x01`，0–100 直值 |
| 色温 | ✅ | option `0x03`，开尔文直值，2700–6500 |
| 绿/品（G/M） | ✅ | option `0x04`，0–100，**50 = 中性** |
| 开关 | ✅ | 走亮度 0 / 上次亮度 |
| 彩色（HSI / tint 模式） | ❌ | 见下方"已知限制" |
| 灯端操作回同步到手机 | ❌ | 见下方"已知限制" |
| HomeKit（Homebridge + mqttthing） | ✅ | 亮度 / 色温 / 开关；桥内延迟实测 **165–236 ms** |
| MQTT 直用 | ✅ | 主题可配，不接 HomeKit 也能用 |

### 已知限制（诚实列出，别当 bug 提）

1. **彩色进不去。** 快速命令的 option 里**没有"模式"这一维**：`0x05 色相` / `0x0C 饱和`
   灯会解析、会回 ACK，但**光完全不变** —— 因为它们只在 tint（彩色）模式下有意义，而模式位只存在于
   `fullCmd` 结构里；这台灯对 `fullCmd` **0 回包 0 生效**（opcode `C0..CF` 全扫过，
   同轮前后各放一条已知生效的快速命令作阳性对照，各回 2 条应答，所以不是链路问题）。
2. **灯不回状态。** `QUERY`（`func=0x01` + needReturn）只拿到一帧**固定 ACK**
   （`01 22 02 01 0000 0000`，设 35 和设 60 回的完全一样），既不带状态也不代表参数有效；
   在灯上转旋钮时桥也**收不到任何主动推送**。所以桥只能发布"最后一次下发的值"。
   还剩一招没试：Config Model Subscription Add（`0x801b`）订阅后再看是否推送。

---

## 快速开始

### 0. 准备

- macOS 12+（Linux 理论可行：`bleak` 走 BlueZ，但**未实测**，见 `docs/TROUBLESHOOTING.md`）
- Python 3.10+
- 灯**通电、且没被手机 App 占着** —— 灯的 BLE 只接受一条连接，NANLINK App 连着的时候电脑连不上

### 1. 装

```bash
git clone https://github.com/<you>/nanlite-wand-bridge && cd nanlite-wand-bridge
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
nanlite-wand selftest                  # 纯计算自检，不需要硬件
```

### 2. 配网（一次性的）

```bash
nanlite-wand scan                      # 确认能看到灯
nanlite-wand provision                 # PB-GATT 配网：现生成随机 NetKey/AppKey 并落盘
nanlite-wand bind                      # 装 AppKey + 绑厂商模型（都有 Config 回执）
```

配网成功与否不看日志措辞，看**回执状态码 `0x00`**：

```
AppKey Add idx0 → 状态 0x00        ✓
Model App Bind idx0 → 状态 0x00    ✓
```

### 3. 直接控

```bash
nanlite-wand set --brightness 40
nanlite-wand set --cct 3200
nanlite-wand set --gm 50           # 50 = 中性
nanlite-wand listen --seconds 30   # 只收不发：验灯会不会主动推状态
```

**判据只有"肉眼看到光变了"**。灯会 ACK 不代表参数生效（见 `docs/PROTOCOL.md` 第 6 节的教训）。

### 4. 接 HomeKit（可选）

需要 `mosquitto` + `homebridge` + `homebridge-mqttthing`：

```bash
brew install mosquitto node
npm -g install --unsafe-perm homebridge homebridge-mqttthing
cp deploy/homebridge-config.sample.json ~/.homebridge/config.json   # 然后改 pin / username
nanlite-wand serve &                                                # 常驻 MQTT 桥
brew services start mosquitto
```

之后在 iOS「家庭」App 里添加配件（配置里的 pin）。
**换网络拓扑要改哪一行、`sf=0` 为什么会让添加界面一直转圈** —— 都在 `docs/HOMEKIT.md`。

macOS 上把桥做成开机常驻服务（含蓝牙权限需要的 `.app` 包装）：

```bash
sudo ./deploy/install-macos.sh        # 生成 LaunchAgent + 签好名的 .app 包装
```

---

## 架构

```
        ┌────────────┐   MQTT    ┌────────────┐  快速命令   ┌──────────┐   BLE    ┌────┐
HomeKit │  Homebridge │ ────────▶ │ bridge.py  │ ──────────▶ │ stack.py │ ───────▶ │灯  │
/ Siri  │  mqttthing  │  主题可配 │  (常驻)    │  commands.py│  协议栈  │          └────┘
        └────────────┘           └────────────┘             └────┬─────┘
                                                        MeshLink │  ← 唯一的传输接口
                                                                 ▼
                                                       link.py 的 BleProxyLink
                                                       （硬件桥替换这一层即可）
```

`nanlite-wand serve` 之外，`cli.py` 里的每条子命令都是独立可跑的 —— 想直接嵌进自己的程序就用
`WandSession` + `WandCommands`：

```python
from nanlite_wand.cli import open_session
from nanlite_wand import commands as CMD
import asyncio

async def main():
    sess = await open_session(...)          # 连灯 + TEA 认证 + 校正单播地址
    c = CMD.WandCommands(sess)
    await c.brightness(40)
    await c.cct(3200)
asyncio.run(main())
```

## 配置

一切"换个人就得改"的值都不在代码里。查找顺序：**命令行 > 环境变量 `NANLITE_*` > 配置文件 > 默认**。

配置文件：`$NANLITE_CONFIG` / `~/.config/nanlite-wand/config.json` / `./nanlite-wand.json`
（模板见 `config.example.json`）。运行期状态（SEQ、rollCode、DeviceKey）落在
`$NANLITE_DATA_DIR`（默认 `~/.local/share/nanlite-wand`）。

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `target_name` | `P24002` | 灯广播名前缀（Nanlite Wand；别的型号改这里） |
| `ble_address` | `null` | 写死地址可跳过扫描（macOS 上是 CoreBluetooth UUID） |
| `net_key`/`app_key`/`dev_key` | `null` | 留空则 `provision` 现生成随机值并写入数据目录 `keys.json` |
| `node_addr` | `2` | 会被 `$FSCCMD001$` 读到的真实单播地址自动校正 |
| `mqtt_host` / `mqtt_port` / `topic_prefix` | `127.0.0.1` / `1883` / `nanlite/wand` | 接什么 broker 你说了算 |
| `status_host` / `status_port` | `127.0.0.1` / `0` | 调试用状态页，**默认只听本机且关闭** |
| `debounce_s` / `resend_gap_s` / `send_pace_s` | `0.1` / `0.1` / `0.06` | 体感延迟主要在这三个 |
| `sync_on_start` | `false` | 重启服务时**不要**擅自改灯（灯渐变慢，会很突兀） |

⚠️ **SEQ 和 rollCode 是全局单调状态**，一台灯只能有一份。同时跑两份代码（比如现场一套 + 仓库一套）
会让它们互相把对方的消息当重放丢掉。

## 仓库导览

| 文件 | 内容 |
| --- | --- |
| `docs/PROTOCOL.md` | 逆向结论全集：配网、密钥、TEA 认证、快速命令、opcode 语义、结论演进与被推翻的假设 |
| `docs/HARDWARE-BRIDGE.md` | **硬件桥开发入口**：`MeshLink` 契约、ESP32-C3/S3 方案、要做/不必做的事 |
| `docs/HOMEKIT.md` | Homebridge/mqttthing 接入、换拓扑改哪行、`sf=0` 与配对重置、mDNS 通告落点 |
| `docs/TROUBLESHOOTING.md` | 按症状索引：连不上 / 认证成功但光不动 / 手机搜不到 / 时延高 |
| `tools/` | 方法学工具：opcode 扫描、option 扫描、fullCmd 对照探针、寄存器复位 |
| `tests/test_bytes.py` | 字节级回归（含与 Mesh 规范一致的 CMAC 向量、自造自解帧） |

## 兼容性说明（刻意做的事）

- **不含任何局域网假设**：不写死 IP、网口名、子网、SSID；MQTT 地址与状态页绑定全部走配置，默认只监听本机。
- **不含任何私人凭据**：Mesh 密钥由你自己的配网现场生成；仓库里的示例值是无效占位。
  唯一"共享"的是**厂商自己的 TEA 密钥**（`docs/PROTOCOL.md` 记录了它的出处与复核方法），
  那是互操作必需的，不是任何人的私有凭据。
- **不含任何人的绝对路径**：数据目录、日志、LaunchAgent 全部由安装脚本按当前 `$HOME` 生成。
- 灯具参数集中在 `commands.py` 的能力矩阵里：换一个型号只需要改 option/标尺，不动协议栈。

## 许可与用途

MIT。用于互操作研究与自有设备控制。要拿它去改卖别人家的产品，请先确认当地法律与厂商条款。

## 致谢

- Feasycom 的 FeasyMesh SDK 与公开文档（TEA 认证与"快速命令"的形态）
- `nicholasmullikin/nanlite`（另一台 Nanlite 机型 FS-300B 的独立逆向，参数编号互相印证）
- vmedea 的 nanlite-protocol 笔记（老机型参数表，`0x05` 是"tint 模式下的色相"这条关键线索来自它）
