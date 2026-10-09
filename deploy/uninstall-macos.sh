#!/usr/bin/env bash
# 只删本安装脚本自己创建的东西；数据目录（密钥/SEQ/日志）默认保留，加 --purge 才删。
set -euo pipefail
LABEL=com.nanlite.wandbridge
APP_DIR="$HOME/Applications/NanliteWandBridge.app"
DATA_DIR="${NANLITE_DATA_DIR:-$HOME/.local/share/nanlite-wand}"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"
rm -rf "$APP_DIR"
if [ "${1:-}" = "--purge" ]; then
  rm -rf "$DATA_DIR"; echo "已连数据目录一起删除：$DATA_DIR"
else
  echo "保留数据目录（含你的 Mesh 密钥与 SEQ）：$DATA_DIR"
fi
echo "卸载完成。TCC 里那条蓝牙授权需要你在 系统设置 → 隐私与安全性 → 蓝牙 手动移除。"
