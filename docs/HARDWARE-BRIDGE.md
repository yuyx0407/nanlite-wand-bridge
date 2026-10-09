# 硬件桥：把这套东西从 Mac 上摘下来

目标：**一块独立的板子**（建议 ESP32-C3 / C6 / S3）常挂在灯旁边，电脑上不再需要常驻进程，
手机/HomeKit/任何 MQTT 客户端直接连板子。

这个仓库已经把接口切好了 —— **协议栈一行都不用改**，只需要换最底下那一层。

---

## 1. 唯一的契约：`MeshLink`

`src/nanlite_wand/link.py` 里的 `MeshLink` 只有 6 个方法。实现者**不需要懂 Mesh**，
只负责"把不透明字节搬进搬出"：

| 方法 | 语义 | BLE 上对应什么 |
| --- | --- | --- |
| `open()` / `close()` / `connected` | 建立并维持到灯的**那一条**连接 | connect + 订阅通知 |
| `send_mesh(frame)` | 发一个 **Mesh 网络 PDU**（已含网络层头，未加密的部分由上层负责） | 写 `0x2ADD` |
| `pop_mesh_frames()` | 一次性取走累积收到的网络 PDU（非阻塞） | `0x2ADE` 通知 |
| `send_vendor(payload)` | 发**厂商私有通道**字节（TEA 认证包、`$FSCCMD…$`） | 写 `0xfff2` |
| `recv_vendor(timeout)` | 取一条厂商通道通知 | `0xfff1` 通知 |

只要这五个动作对得上，`stack.py` / `auth.py` / `commands.py` / `bridge.py` 全部照常工作。
`BleProxyLink` 就是当前唯一实现。

### 已验证过的等价性

`tests/test_bytes.py` + 与现场旧实现的逐字节对比都表明：**同一输入产出的帧完全一致**
（30 字节网络 PDU、NID/AID、`vendor_opcode`、快速命令载荷）。所以换传输时只要保证
"字节搬运不失真"，行为就不会变。

---

## 2. 两条实现路线

### 路线 A：透传dongle（**推荐先做这个**）

板子只做 BLE central，把两条 GATT 通道原样转发出来（TCP / 串口 / WebSocket / MQTT 均可）。
Python 侧新写一个 `SocketLink(MeshLink)`（约 60 行），协议逻辑仍在主机上。

```python
# 伪代码：板子暴露一个行分隔的 RPC
> {"t":"mesh","hex":"000ec101e918..."}        # 发一个网络 PDU
< {"t":"mesh","hex":"000e2eb0f484..."}        # 收到的网络 PDU（可多条）
> {"t":"vendor","hex":"41555448..."}          # 发厂商字节
< {"t":"vendor","hex":"41555448..."}          # 厂商通知
> {"t":"state"}  < {"connected":true,"mtu":247}
```

固件侧要做的事（BLE 协议栈本身就会做的事）：

1. 扫描 `P24002`（或配置的名字 / 服务 `0x1828`）并连接；断线自动重连。
2. 订阅 `0x2ADE` 与 `0xfff1`；把通知**逐条、不拼接、不截断**地转发（MTU 协商到 247 左右）。
3. 收到主机的 PDU 就 `write characteristic(without response)`，**保持字节顺序**。
4. 可选：`0x1827`（PB-GATT 配网通道）也转发出来，这样配网也能由板子完成；
   不转发的话就先用 Mac 配一次网，之后板子只做运行时中继（完全够用）。

优点：固件极薄、风险低、协议升级不用重烧板子；调试时同一份 Python 代码在 Mac 和板子上都能跑。

### 路线 B：板子上跑完整 Mesh 栈

用 ESP-IDF 的 Mesh 组件（或 Feasycom 自己的 FeasyMesh SDK）在设备上实现网络层/传输层/Access 层，
主机侧只发"设置亮度 40"这种语义命令。要做对这些才可能成功：

- TEA 认证（`docs/PROTOCOL.md` 第 3 节）必须在**每次连接后**做，且轮数 32 优先；
- 网络层加密参数：NID 混淆、AES-CCM（NetMIC 4 字节）、IV Index、SEQ；
- 上层传输：≤11 字节载荷走未分段，否则分片（12 字节/片，SZMIC=0，SeqZero 取第一片 SEQ）；
- AppKey 索引与厂商模型绑定（`Model App Bind` 的参数是**小端**，见 `keysetup.py` 的注释）。

代价：把两周的逆向工作在新语言里重做一遍。除非你的目标就是"完全不要主机"，否则先走 A。

---

## 3. 无论走哪条路都必须遵守的硬约束

| 约束 | 后果 | 处理 |
| --- | --- | --- |
| **灯只接受一条 BLE 连接** | 手机 App 连着时电脑连不上，反之亦然 | 板子独占；调试时要有"让桥别碰蓝牙"的维护锁（`serve` 用 `$NANLITE_DATA_DIR/maintenance.lock`） |
| **SEQ 必须严格递增且只有一份** | 回退/重复的 SEQ 被**静默丢弃**，看起来像"命令偶发失灵" | 存 NVS/Flash，掉电不丢；不要两个进程各自维护 |
| **rollCode 必须递增** | 固定值会被丢 | 同上，落盘持久化 |
| **每次连接都要重新 TEA 认证** | 不认证时灯照样解密回显，但光不动 | 认证失败要显式报错，别静默继续 |
| **控制目标地址从 `$FSCCMD001$` 读** | 猜地址会打到别的节点或无人应答 | 连接后校正（本项目已实现） |
| 参数是非易失的 | 遍历参数做实验会把灯写脏 | 实验脚本必须自带复位（`tools/tint_reset.py`） |

---

## 4. 延迟预算（硬件侧能改善什么）

桥内软件部分实测 165–236 ms，其中大头是**去抖 100 ms** 与每条命令 **60 ms 发送间隔**。
真正下不去的是：BLE 连接间隔 + Feasycom 从 GATT 转进 Mesh 的那一跳。

硬件桥可以动的三件事：

1. **连接参数**：作为 central 主动请求更短的 connection interval（30 ms 以下）、
   或让外设不要进入低功耗（`latency=0`、supervision timeout 放宽）。
2. **去掉软件节流**：透传链路上 `send_pace_s` 可以从 0.06 压到 0.01~0.02
   （注意 write-without-response 的流控，压太狠会丢包，要用阳性对照验）。
3. **把去抖挪到发起端**：HomeKit 自己就会节流；桥内去抖是为了保护 Mesh 拥塞，
   如果链路更可靠，`debounce_s` 可以降到 0.03~0.05。

**验收方式**：不要靠手感。桥每次改动都打一行 `时延：…ms（桥内合计）`，
换实现前后各测 10 次取分布。

---

## 5. 里程碑清单

- [ ] `SocketLink(MeshLink)` 实现 + 单元测试（用假 link 驱动 `WandCommands`，检查产出的帧）
- [ ] 板子固件：扫描/连接/订阅/双通道转发 + 断线重连
- [ ] 同一盏灯上交叉验证：`BleProxyLink` 与 `SocketLink` 分别下发同一命令，
      **灯的表现必须一致**（这一步是唯一可信的等价性证明）
- [ ] SEQ/rollCode 迁移到板子上的持久存储，并验证重启后仍能控制（重放保护测试）
- [ ] 常驻服务从 Mac 挪到板子：`serve` 的 MQTT 部分直接跑在板子上（或仍跑在主机，link 指过去）
- [ ] HomeKit 侧零改动验证（`docs/HOMEKIT.md`）

### 明确不建议做的

- **彩色模式**：卡在灯固件（tint 模式进不去），换硬件桥不会让它变通；
- **灯端状态回同步**：灯既不响应查询也不主动推，除非先证明"订阅之后会推"，
  否则桥只能继续发布最后命令值（`nanlite-wand listen` 可复查）。

---

## 6. 现成的可复用件（做桥时直接拿走）

| 文件 | 为什么它能独立复用 |
| --- | --- |
| `commands.py` | 纯函数：option/标尺/能力矩阵/字节构造，不碰 IO |
| `stack.py` | 只依赖 `MeshLink`，负责 Mesh 编解码与会话 |
| `auth.py` | 只依赖 link 的两个 vendor 方法，TEA + 诊断命令 |
| `crypto.py` / `net.py` | 纯计算，含规范向量自检 |
| `keysetup.py` | Config 层三步（装 AppKey / 绑模型 / TTL 探针），有回执可判 |
| `link.py` | **就是要替换的那一层**，含接口定义与 BLE 参考实现 |
| `tools/` | 移植新机型时的探针与复位脚本 |

移植别的 Nanlite 机型时基本只会动两处：`commands.py` 的 option/标尺表，
和 `link.py` 里 `TARGET_NAME` / 服务 UUID。
