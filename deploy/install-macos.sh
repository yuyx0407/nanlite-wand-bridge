#!/usr/bin/env bash
# install-macos.sh —— 把常驻桥装成你当前用户的 LaunchAgent（**不要用 sudo**）
#
# 为什么需要 .app 包装：macOS 的 TCC 要求任何碰蓝牙的进程带
# NSBluetoothAlwaysUsageDescription，否则直接被 SIGABRT（退出码 134，日志里什么也没有）。
# 所以这里生成一个最小的 .app 壳，让 launchd 通过它去跑 python。
#
# 全程只写：仓库内的 .venv、~/Applications/*.app、~/Library/LaunchAgents/*.plist、
# 以及数据目录（默认 ~/.local/share/nanlite-wand）。卸载见 uninstall-macos.sh。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL=com.nanlite.wandbridge
APP_NAME=NanliteWandBridge
APP_DIR="$HOME/Applications/$APP_NAME.app"
DATA_DIR="${NANLITE_DATA_DIR:-$HOME/.local/share/nanlite-wand}"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
PY="$HERE/.venv/bin/python"

echo "① 建虚拟环境并装依赖"
[ -x "$PY" ] || python3 -m venv "$HERE/.venv"
"$PY" -m pip install --quiet --upgrade pip
"$PY" -m pip install --quiet -e "$HERE"

mkdir -p "$DATA_DIR" "$APP_DIR/Contents/MacOS"

echo "② 生成 .app 壳（蓝牙用途声明 + 强制 native 架构）"
cat > "$APP_DIR/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>$APP_NAME</string>
  <key>CFBundleIdentifier</key><string>local.nanlite.$APP_NAME</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSUIElement</key><true/>
  <key>NSBluetoothAlwaysUsageDescription</key>
  <string>需要蓝牙来连接并控制 Nanlite 灯具（Mesh Proxy 与厂商认证通道）。</string>
</dict></plist>
PLIST

cat > "$APP_DIR/Contents/MacOS/$APP_NAME" <<RUNNER
#!/bin/bash
# 注意：不要用 uname -m 判断架构 —— 在 Rosetta 下它自己会撒谎。
ARCH=()
[ "\$(sysctl -n hw.optional.arm64 2>/dev/null)" = "1" ] && ARCH=(arch -arm64)
export NANLITE_DATA_DIR="\${NANLITE_DATA_DIR:-$DATA_DIR}"
export PYTHONUNBUFFERED=1
LOG="\$NANLITE_DATA_DIR/bridge.log"
exec "\${ARCH[@]}" "$PY" -u -m nanlite_wand serve >>"\$LOG" 2>&1
RUNNER
chmod +x "$APP_DIR/Contents/MacOS/$APP_NAME"
# ad-hoc 签名：TCC 记住的是签名后的二进制身份，重新生成后要再签一次
codesign --force --sign - "$APP_DIR" >/dev/null 2>&1 || codesign --force --sign - "$APP_DIR"

echo "③ 生成 LaunchAgent（登录即起、崩了自动拉起）"
cat > "$PLIST" <<AGENT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$APP_DIR/Contents/MacOS/$APP_NAME</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>15</integer>
  <key>EnvironmentVariables</key><dict>
    <key>NANLITE_DATA_DIR</key><string>$DATA_DIR</string>
    <key>NANLITE_CONFIG</key><string>${NANLITE_CONFIG:-$HOME/.config/nanlite-wand/config.json}</string>
  </dict>
</dict></plist>
AGENT
plutil -lint "$PLIST" >/dev/null

echo "④ 载入服务"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

cat <<DONE

完成。

  日志     : $DATA_DIR/bridge.log
  数据目录 : $DATA_DIR   （seq.txt / roll.txt / keys.json / state.json / maintenance.lock）
  配置     : ${NANLITE_CONFIG:-$HOME/.config/nanlite-wand/config.json}（模板见仓库 config.example.json）

第一次跑会在你登录后弹一次蓝牙授权；允许之后就会一直常驻。
临时让桥不要碰蓝牙（跑 tools/ 里的探针前必做）：

    touch "$DATA_DIR/maintenance.lock"      # 桥会主动断开并保持不连
    rm      "$DATA_DIR/maintenance.lock"    # 交还控制权

验证： tail -f "$DATA_DIR/bridge.log"   应该看到 认证通过 + Mesh: 已连接
DONE
