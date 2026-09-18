#!/bin/bash
# 生成 e2e 用的真实媒体样本文件。
# 全部本地合成，不含任何第三方素材；产物在 samples/（已 gitignore）。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/samples"
BIG_MB="${BIG_MB:-64}"

need() { command -v "$1" >/dev/null || { echo "缺少依赖: $1"; exit 1; }; }
need ffmpeg
need cupsfilter

mkdir -p "$OUT"

echo "==> sample.txt"
{
  echo "GocryptKit e2e sample text"
  echo "生成时间无关，内容确定性可复现。"
  for i in $(seq 1 2000); do
    printf 'line %05d  the quick brown fox jumps over the lazy dog  中文内容测试\n' "$i"
  done
} > "$OUT/sample.txt"

echo "==> sample.pdf"
cupsfilter "$OUT/sample.txt" > "$OUT/sample.pdf" 2>/dev/null

echo "==> sample.mp3  (5s 440Hz 正弦波)"
ffmpeg -hide_banner -loglevel error -y \
  -f lavfi -i "sine=frequency=440:duration=5" \
  -codec:a libmp3lame -b:a 128k "$OUT/sample.mp3"

echo "==> sample.mp4  (5s 320x240 测试图 + 音轨)"
ffmpeg -hide_banner -loglevel error -y \
  -f lavfi -i "testsrc=size=320x240:rate=15:duration=5" \
  -f lavfi -i "sine=frequency=330:duration=5" \
  -codec:v libx264 -pix_fmt yuv420p -codec:a aac -shortest "$OUT/sample.mp4"

echo "==> sample-large.bin  (${BIG_MB} MB，用于吞吐与大文件完整性)"
dd if=/dev/urandom of="$OUT/sample-large.bin" bs=1m count="$BIG_MB" 2>/dev/null

echo
ls -lh "$OUT"
