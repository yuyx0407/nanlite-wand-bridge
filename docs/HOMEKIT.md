# 接到 HomeKit（Homebridge + mqttthing）

链路：

```
iPhone 家庭App ──WiFi──▶ Homebridge(51826) ──▶ homebridge-mqttthing ──▶ MQTT broker
                                                                    ▲
                                            nanlite-wand serve ─────┘（订阅 set/*，发布状态/*）
```

灯的状态**不由灯提供**（见 `docs/PROTOCOL.md` 第 6 节），所以桥发布的是"最后一次下发的值"。

---

## 1. 装

```bash
brew install mosquitto node
brew services start mosquitto
npm -g install --unsafe-perm homebridge homebridge-mqttthing
```

## 2. 配 Homebridge

```bash
cp deploy/homebridge-config.sample.json ~/.homebridge/config.json
```

必须自己改的两项：

| 键 | 要求 |
| --- | --- |
| `bridge.username` | 配对用的 MAC 形式 ID，**每台桥唯一**；改了要重新配对 |
| `bridge.pin` | 添加配件时输入的 8 位码（Home App 里"手动输入"要输**不带横线**的 8 位） |

MQTT 主题（`nanlite/wand/*`）与桥的默认 `topic_prefix` 一致；改前缀要两边同步。
配置里刻意**不含**任何 IP 或网口名 —— 见下一节。

## 3. 起

```bash
nanlite-wand serve          # 或 ./deploy/install-macos.sh 装成常驻服务
homebridge                  # 先前台跑一次，确认没有报错
```

## 4. 添加配件（以及它为什么可能搜不到）

iOS「家庭」App → 添加配件 → 更多支付配件 → 输入 `config.json` 里的 pin。

**多网卡机器上最常见的一次失败：mDNS 通告发到了别的接口。**
手机连的 Wi-Fi 和桥的通告不在同一个二层域，就会表现为"一直转圈、列表空、不报错"。

Homebridge 2.x 里**能限制通告网口的键只有 `bridge.bind`**：

```jsonc
"bridge": { ..., "bind": "<你的接口名>" }     // 例："en0"、"eth0"、"wlan0"
```

⚠️ 三个真实坑：

1. 1.x 时代的 `bridge.interfaces` 在 **2.4.0 里已经不存在，写了会被静默忽略**
   （源码只往下传 `bind` 与 `advertiser`）。忽略了 `bind` 之后广告商会自己挑一个"最好"的网口，
   经常挑到上联口 —— 于是手机永远看不到。
2. `bind` **要填接口名，不要填 IP**：填 IP 会让广播里一条 A 记录都不发（更糟）。
3. `advertiser` 留空也是 ciao（`hap-nodejs` 里 `info.advertiser ??= "ciao"`），不必专门设。

### 本机就能验收（不用碰手机）

接口编号**必须换算**，不要按 `ifconfig -l` / `ip a` 的排列顺序数：

```bash
python3 -c "import socket;print(socket.if_nameindex())"   # 找到你那个接口的 index
dns-sd -B _hap._tcp local                # 期望：出现该 index 那一行
dns-sd -G v4 <实例名>.local              # 期望：地址就是这台机器在该接口上的 IP
dns-sd -L "<实例名>" _hap._tcp local     # 期望：TXT 里 sf=1
```

（Linux 上 `avahi-browse -t _hap._tcp` 与 `dig -x`/`getent hosts` 起同样作用。）

## 5. `sf=0` —— 最阴的一次失败

**在 Home App 里"移除配件"不会通知 Homebridge。** 桥自己那份配对记录还在，
于是它对外声明 `sf=0`（=已配对、不接受新配对），添加界面的表现就是**一直转圈、列表空、不报错，
手动输配对码也说无效**。

处理：把配对持久化文件**挪走**（别直接删，留个备份目录），再重启 Homebridge：

```bash
mkdir -p ~/.homebridge/persist-backup-$(date +%Y%m%d)
mv ~/.homebridge/persist/AccessoryInfo.<USERNAME去冒号>.json \
   ~/.homebridge/persist/IdentifierCache.<USERNAME去冒号>.json \
   ~/.homebridge/persist-backup-$(date +%Y%m%d)/
```

之后 `dns-sd -L` 里应看到 **`sf=1`**。`bridge.username` 不要改（改了配对关系更乱）。

## 6. 状态只有两栏是正常的

本项目的灯能做的只有：开关、亮度、色温（绿/品是第三个可选参数，HomeKit 没有对应特征，
不接进 HomeKit，可用 `nanlite-wand set --gm` 或 MQTT 直接调）。
**色相/饱和度刻意没有接** —— 那台灯进不了 tint 模式，接进来就是两个静默失效的死控件。
（能力矩阵见 `README.md`；`commands.py` 支持后只要在配置里加回 `setHue/getHue/setSaturation/getSaturation`
四组主题即可。）

## 7. 延迟调参

桥内每改一次会打一行分解，别靠手感调：

```
时延：MQTT→唤醒 2ms + 去抖 101ms + 节流 0ms + 下发 64ms = 167ms（桥内合计）
```

| 在哪 | 键 | 默认 |
| --- | --- | --- |
| 合并滑块连发 | `debounce_s`（开/关点击**不走**去抖） | 0.10 |
| 两条指令最小间隔 | `resend_gap_s` | 0.10 |
| 每条 BLE 写之后的间隔 | `send_pace_s` | 0.06 |
| mqttthing 侧重试/入站去抖 | `confirmationPeriodms`、`debounceRecvms` | 500、150 |

再往下压就是拿"拖动滑块时 Mesh 拥塞"换延迟，不建议。物理下限（BLE 连接间隔 +
Feasycom 从 GATT 转进 Mesh 的一跳 + 灯自己的渐变）不在软件手里。

## 8. 远程与自动化

- 没有 HomeKit 中枢（HomePod / Apple TV）时，只有**同一局域网内**可控，Home App 会显示"无远程访问"。
- 想让自动化更稳：把灯建在同一个桥里、避免用"配件已启用"做触发条件。
- 想在 HomeKit 之外用：直接发 MQTT 就行 ——
  `nanlite/wand/set/on|brightness|colorTemperature|gm|raw`，`raw` 可注入任意厂商 AccessPDU 做实验。
