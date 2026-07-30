#!/bin/bash
# 検証処理の実体は scripts/validate.sh です（Makefile の validate ターゲットや
# ポータルの validate アクションもそちらを呼び出します）。
# 二重管理を避けるため、このファイルは引数をそのまま転送するラッパーです。
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${ROOT_DIR}/scripts/validate.sh"

if [ ! -f "$TARGET" ]; then
  echo "検証スクリプトが見つかりません: ${TARGET}" >&2
  exit 1
fi

exec bash "$TARGET" "$@"
