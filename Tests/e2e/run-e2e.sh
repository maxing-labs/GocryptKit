#!/bin/bash
# GocryptKit 端到端验收：用真实媒体文件（txt / pdf / mp3 / mp4 / 大二进制）
# 走完整挂载 → 写入 → 校验 → 卸载 → 重挂载 → 回读校验链路。
#
# 前提：GocryptKit.app 已装入 /Applications 且 FSKit 扩展已在
#      「系统设置 → 登录项与扩展 → 文件系统扩展」中启用。
#
# 用法：./run-e2e.sh            正常跑
#      KEEP=1 ./run-e2e.sh     失败时保留现场不清理
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
if [ -z "${APP:-}" ] || [ ! -x "$APP" ]; then
  CANDIDATE="/Applications/GocryptKit.app/Contents/MacOS/GocryptKit"
  LOCAL_BUILD="$REPO/build/DerivedData/Build/Products/Debug/GocryptKit.app/Contents/MacOS/GocryptKit"
  if [ -x "$CANDIDATE" ]; then
    APP="$CANDIDATE"
  elif [ -x "$LOCAL_BUILD" ]; then
    APP="$LOCAL_BUILD"
  else
    DERIVED_APP="$(find ~/Library/Developer/Xcode/DerivedData/GocryptKit-*/Build/Products/Debug/GocryptKit.app/Contents/MacOS/GocryptKit 2>/dev/null | head -n 1)"
    if [ -n "$DERIVED_APP" ] && [ -x "$DERIVED_APP" ]; then
      APP="$DERIVED_APP"
    else
      APP="$CANDIDATE"
    fi
  fi
fi
FIXTURE="$REPO/Tests/fixtures/v1.3"
SAMPLES="$HERE/samples"
PASSWORD="${PASSWORD:-test}"

CIPHER="$(cd "$(mktemp -d /tmp/gocryptfs-e2e-cipher.XXXXXX)" && pwd -P)"
MOUNT="$(cd "$(mktemp -d /tmp/gocryptfs-e2e-mount.XXXXXX)" && pwd -P)"

# 第 11 段起用的是自己新建的卷，和上面的金标准夹具完全无关。
NEWCIPHER="$(cd "$(mktemp -d /tmp/gocryptfs-e2e-newcipher.XXXXXX)" && pwd -P)"
NEWMOUNT="$(cd "$(mktemp -d /tmp/gocryptfs-e2e-newmount.XXXXXX)" && pwd -P)"
NEWPASSWORD="${NEWPASSWORD:-e2e-fresh-vault-$$}"

PASS=0; FAIL=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
step() { printf '\n\033[1m── %s\033[0m\n' "$1"; }
cmp_hash() { # name expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1  期望 ${2:0:16}… 实得 ${3:0:16}…"; fi
}

cleanup() {
  for m in "$MOUNT" "$NEWMOUNT" "${NEWMOUNT}_READ_ONLY"; do
    if mount | grep -q " $m "; then "$APP" umount "$m" >/dev/null 2>&1; fi
  done
  if [ "${KEEP:-0}" = "1" ] && [ "$FAIL" -gt 0 ]; then
    echo "现场保留: cipher=$CIPHER mount=$MOUNT"
    echo "          newcipher=$NEWCIPHER newmount=$NEWMOUNT"
  else
    rm -rf "$CIPHER" "$MOUNT" "$NEWCIPHER" "$NEWMOUNT" "${NEWMOUNT}_READ_ONLY"
  fi
}
trap cleanup EXIT

# 冷启动时扩展首次 probe 会失败，需要重试（已知行为，见 docs）
# 用法：mount_vault [cipher] [mount] [password]
mount_vault() {
  local cipher="${1:-$CIPHER}" mnt="${2:-$MOUNT}" pw="${3:-$PASSWORD}"
  local i
  for i in 1 2 3; do
    if printf '%s\n' "$pw" | "$APP" mount "$cipher" "$mnt" --password-stdin >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# 挂载必须失败（密码错、或压根不该能开）。成功了就是 bug，顺手卸掉别留现场。
# 用法：mount_must_fail <断言名> <cipher> <mount> <password>
mount_must_fail() {
  if printf '%s\n' "$4" | "$APP" mount "$2" "$3" --password-stdin >/dev/null 2>&1; then
    bad "$1"
    "$APP" umount "$3" >/dev/null 2>&1
  else
    ok "$1"
  fi
}

# 绕过宿主 App 直接调 /sbin/mount：此时 Keychain 里没有该卷的凭据，
# 扩展必须拒绝。这同时证明了两件事：凭据确实被清除了，且扩展内不存在
# 任何硬编码的兜底密码。
# 用法：direct_mount_must_fail <断言名> [cipher]
direct_mount_must_fail() {
  local cipher="${2:-$CIPHER}" probe
  probe="$(cd "$(mktemp -d /tmp/gocryptfs-e2e-probe.XXXXXX)" && pwd -P)"
  if /sbin/mount -t gocryptfs "$cipher" "$probe" >/dev/null 2>&1; then
    bad "$1"
    "$APP" umount "$probe" >/dev/null 2>&1
  else
    ok "$1"
  fi
  rmdir "$probe" 2>/dev/null
}

# init 必须失败。同时确认它没有留下半成品：失败后目录里不该多出 gocryptfs.conf。
# 用法：init_must_fail <断言名> <目录> [init 的额外参数...]
init_must_fail() {
  local label="$1" dir="$2"; shift 2
  if "$APP" init "$dir" "$@" </dev/null >/dev/null 2>&1; then
    bad "$label"
  elif [ -e "$dir/gocryptfs.conf" ]; then
    bad "$label（被拒绝了，却留下了 gocryptfs.conf）"
  else
    ok "$label"
  fi
}

perms_of() { stat -f %Lp "$1" 2>/dev/null; }

step "0. 前置检查"
[ -x "$APP" ] || { bad "找不到 $APP"; exit 1; }
ok "宿主 App 存在"
if "$APP" status 2>/dev/null | grep -q ENABLED; then ok "FSKit 扩展已启用"; else bad "FSKit 扩展未启用"; exit 1; fi
[ -d "$SAMPLES" ] || { echo "样本缺失，先跑 ./make-samples.sh"; exit 1; }
ok "样本文件就绪 ($(ls "$SAMPLES" | wc -l | tr -d ' ') 个)"

step "1. 准备可写密文卷（金标准夹具副本）"
cp -R "$FIXTURE"/. "$CIPHER"/
ok "夹具已复制到 $CIPHER"

step "1.5 无凭据时必须拒绝挂载"
direct_mount_must_fail "无 Keychain 凭据时扩展拒绝解锁（无硬编码兜底密码）"

step "2. 挂载"
if mount_vault; then ok "挂载成功"; else bad "挂载失败"; exit 1; fi
mount | grep -q " $MOUNT " && ok "出现在 mount 表中" || bad "未出现在 mount 表中"
[ "$(cat "$MOUNT/status.txt" 2>/dev/null)" = "It works!" ] && ok "夹具原有内容可读" || bad "夹具原有内容读取失败"

step "3. 写入真实媒体文件"
declare -a NAMES=()
for f in "$SAMPLES"/*; do
  n="$(basename "$f")"
  NAMES+=("$n")
  cp "$f" "$MOUNT/$n" || bad "写入 $n 失败"
done
ok "已写入 ${#NAMES[@]} 个文件"

step "4. 挂载点内校验（写后即读）"
for n in "${NAMES[@]}"; do
  src=$(shasum -a 256 "$SAMPLES/$n" | awk '{print $1}')
  dst=$(shasum -a 256 "$MOUNT/$n"   | awk '{print $1}')
  cmp_hash "$n  SHA256 一致" "$src" "$dst"
done

step "5. 文件格式可被应用正确解析"
# PDF：魔数 + 页数
head -c 5 "$MOUNT/sample.pdf" | grep -q '%PDF-' && ok "sample.pdf 魔数正确" || bad "sample.pdf 魔数错误"
# 用 QuickLook 实际渲染一张缩略图：证明系统组件能从加密卷上解析整个 PDF
qldir=$(mktemp -d); qlmanage -t -s 256 -o "$qldir" "$MOUNT/sample.pdf" >/dev/null 2>&1
if ls "$qldir"/*.png >/dev/null 2>&1; then ok "sample.pdf QuickLook 渲染成功"; else bad "sample.pdf QuickLook 渲染失败"; fi
rm -rf "$qldir"
# MP3 / MP4：ffprobe 读出的时长与源一致
for m in sample.mp3 sample.mp4; do
  d_src=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$SAMPLES/$m" 2>/dev/null | cut -d. -f1)
  d_dst=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$MOUNT/$m"   2>/dev/null | cut -d. -f1)
  if [ -n "$d_dst" ] && [ "$d_src" = "$d_dst" ]; then ok "$m ffprobe 时长一致 (${d_dst}s)"; else bad "$m ffprobe 解析失败 (源=$d_src 挂载=$d_dst)"; fi
done
# MP4 完整解码一遍，确认块级读取无损
ffmpeg -hide_banner -loglevel error -v error -i "$MOUNT/sample.mp4" -f null - 2>/dev/null \
  && ok "sample.mp4 完整解码无报错" || bad "sample.mp4 解码报错"

step "6. 随机访问读取（模拟播放器 seek）"
for off in 0 1 7 63; do
  a=$(dd if="$SAMPLES/sample-large.bin" bs=1m skip=$off count=1 2>/dev/null | shasum -a 256 | awk '{print $1}')
  b=$(dd if="$MOUNT/sample-large.bin"   bs=1m skip=$off count=1 2>/dev/null | shasum -a 256 | awk '{print $1}')
  cmp_hash "偏移 ${off}MB 处 1MB 块一致" "$a" "$b"
done
if python3 -c '
import os, sys, random
src_p = "'"$SAMPLES"'/sample-large.bin"
dst_p = "'"$MOUNT"'/sample-large.bin"
fd_s = os.open(src_p, os.O_RDONLY)
fd_d = os.open(dst_p, os.O_RDONLY)
size = os.path.getsize(src_p)
for chunk in [4096, 65536, 131072, 262144, 524288, 1048576, 2097152]:
    for _ in range(5):
        off = random.randint(0, size - chunk)
        s = os.pread(fd_s, chunk, off)
        d = os.pread(fd_d, chunk, off)
        if s != d:
            sys.exit(1)
os.close(fd_s)
os.close(fd_d)
' 2>/dev/null; then
  ok "Python 大块随机 pread (4KB~2MB) 均通过"
else
  bad "Python 大块随机 pread 失败 (可能存在 EIO 或截断)"
fi

step "7. 吞吐基线"
size_mb=$(( $(stat -f %z "$SAMPLES/sample-large.bin") / 1048576 ))
t0=$(date +%s.%N); cp "$SAMPLES/sample-large.bin" "$MOUNT/throughput.bin"; sync; t1=$(date +%s.%N)
w=$(echo "$size_mb / ($t1 - $t0)" | bc -l)
t0=$(date +%s.%N); cat "$MOUNT/throughput.bin" > /dev/null; t1=$(date +%s.%N)
r=$(echo "$size_mb / ($t1 - $t0)" | bc -l)
printf '  写入 %.1f MB/s   读取 %.1f MB/s  (%d MB)\n' "$w" "$r" "$size_mb"
ok "吞吐测量完成"

step "8. 卸载并检查密文落盘"
"$APP" umount "$MOUNT" >/dev/null 2>&1 && ok "卸载成功" || bad "卸载失败"
mount | grep -q " $MOUNT " && bad "卸载后仍在 mount 表中" || ok "已从 mount 表移除"
leak=0
for n in "${NAMES[@]}"; do
  if ls "$CIPHER" | grep -qF "$n"; then bad "密文目录泄漏明文文件名: $n"; leak=1; fi
done
[ "$leak" = "0" ] && ok "密文目录无明文文件名泄漏"

step "8.5 卸载后凭据已失效"
direct_mount_must_fail "卸载后凭据已清除，无法再免密挂载"

step "9. 重新挂载回读（持久化）"
if mount_vault; then ok "重新挂载成功"; else bad "重新挂载失败"; exit 1; fi
for n in "${NAMES[@]}"; do
  src=$(shasum -a 256 "$SAMPLES/$n" | awk '{print $1}')
  dst=$(shasum -a 256 "$MOUNT/$n"   | awk '{print $1}')
  cmp_hash "$n  重挂载后仍一致" "$src" "$dst"
done
[ "$(cat "$MOUNT/status.txt" 2>/dev/null)" = "It works!" ] && ok "夹具原有内容仍完好" || bad "夹具原有内容损坏"

step "10. 收尾卸载"
"$APP" umount "$MOUNT" >/dev/null 2>&1 && ok "卸载成功" || bad "卸载失败"

# ══════════════════════════════════════════════════════════════════════════
# 以下不碰任何预置夹具：卷是这里现建的，从 init 一路验到重挂载回读。
# ══════════════════════════════════════════════════════════════════════════

step "11. 创建新 vault（不依赖预置夹具）"
init_must_fail "无 --password-stdin 且非终端时拒绝创建" "$NEWCIPHER"
init_must_fail "已废弃的 --password 参数直接拒绝" "$NEWCIPHER" --password "$NEWPASSWORD"
if printf '\n' | "$APP" init "$NEWCIPHER" --password-stdin >/dev/null 2>&1; then
  bad "空密码时拒绝创建"
else
  ok "空密码时拒绝创建"
fi
[ -z "$(ls -A "$NEWCIPHER")" ] && ok "被拒绝的创建没有弄脏目录" || bad "被拒绝的创建留下了文件"

if printf '%s\n' "$NEWPASSWORD" | "$APP" init "$NEWCIPHER" --password-stdin >/dev/null 2>&1; then
  ok "创建新 vault 成功"
else
  bad "创建新 vault 失败"; exit 1
fi
[ -f "$NEWCIPHER/gocryptfs.conf" ]  && ok "生成了 gocryptfs.conf"  || bad "缺少 gocryptfs.conf"
[ -f "$NEWCIPHER/gocryptfs.diriv" ] && ok "生成了根目录 gocryptfs.diriv" || bad "缺少 gocryptfs.diriv"
[ "$(perms_of "$NEWCIPHER/gocryptfs.conf")" = "400" ] \
  && ok "gocryptfs.conf 权限为 0400" || bad "gocryptfs.conf 权限为 $(perms_of "$NEWCIPHER/gocryptfs.conf")，期望 400"
[ "$(stat -f %z "$NEWCIPHER/gocryptfs.diriv")" = "16" ] \
  && ok "gocryptfs.diriv 为 16 字节" || bad "gocryptfs.diriv 大小异常"
# conf + diriv + 一个加密的 .fseventsd 目录（见下面第 13 段）
[ "$(ls -A "$NEWCIPHER" | wc -l | tr -d ' ')" = "3" ] \
  && ok "目录里只有预期的三项（无 .tmp 残骸）" || bad "目录里有预期之外的文件: $(ls -A "$NEWCIPHER" | tr '\n' ' ')"

# 覆盖已有的 gocryptfs.conf 等于用新 master key 换掉旧的，里面的密文将永远
# 解不开 —— 所以重复 init 必须拒绝，且原文件一个字节都不能动。
conf_before=$(shasum -a 256 "$NEWCIPHER/gocryptfs.conf" | awk '{print $1}')
if printf '%s\n' "another-password" | "$APP" init "$NEWCIPHER" --password-stdin >/dev/null 2>&1; then
  bad "对已有 vault 重复 init 竟然成功了"
else
  ok "拒绝覆盖已有的 vault"
fi
cmp_hash "已有 gocryptfs.conf 未被改动" "$conf_before" "$(shasum -a 256 "$NEWCIPHER/gocryptfs.conf" | awk '{print $1}')"

nonempty="$(cd "$(mktemp -d /tmp/gocryptfs-e2e-nonempty.XXXXXX)" && pwd -P)"
echo "我的报税表" > "$nonempty/taxes.txt"
if printf '%s\n' "$NEWPASSWORD" | "$APP" init "$nonempty" --password-stdin >/dev/null 2>&1; then
  bad "拒绝在非空目录里创建（已有文件不会被加密）"
elif [ -e "$nonempty/gocryptfs.conf" ]; then
  bad "拒绝在非空目录里创建（已有文件不会被加密）（被拒绝了，却留下了 gocryptfs.conf）"
else
  ok "拒绝在非空目录里创建（已有文件不会被加密）"
fi
[ -f "$nonempty/taxes.txt" ] && ok "非空目录里的原有文件毫发无损" || bad "非空目录里的文件被动过"
rm -rf "$nonempty"

# 可选：拿上游 gocryptfs 做格式一致性交叉验证
if command -v gocryptfs >/dev/null 2>&1; then
  info=$(gocryptfs -info "$NEWCIPHER" 2>&1)
  echo "$info" | grep -q "EMENames" && echo "$info" | grep -q "AES-GCM-256" \
    && ok "上游 gocryptfs -info 能解析我们写的 conf" \
    || bad "上游 gocryptfs -info 解析异常: $info"
else
  printf '  \033[33m-\033[0m 未安装 gocryptfs CLI，跳过上游格式交叉验证\n'
fi

step "12. 新 vault 的凭据边界"
direct_mount_must_fail "未存凭据时扩展拒绝解锁新 vault" "$NEWCIPHER"
mount_must_fail "错误密码无法挂载新 vault" "$NEWCIPHER" "$NEWMOUNT" "definitely-not-$NEWPASSWORD"

step "13. 挂载新 vault 并写入媒体样本"
if mount_vault "$NEWCIPHER" "$NEWMOUNT" "$NEWPASSWORD"; then ok "新 vault 挂载成功"; else bad "新 vault 挂载失败"; exit 1; fi
mount | grep -q " $NEWMOUNT " && ok "新 vault 出现在 mount 表中" || bad "新 vault 未出现在 mount 表中"
# 刚建的卷里除了我们自己放的 .fseventsd 标记，应该什么都没有
stray=$(ls -A "$NEWMOUNT" 2>/dev/null | grep -v '^\.' | wc -l | tr -d ' ')
[ "$stray" = "0" ] && ok "新 vault 初始为空" || bad "新 vault 初始不为空（$stray 项）"

# init 时预置的 no_log 让 macOS 的 fseventsd 闭嘴，否则它会往卷里持续写
# 变更日志，再随密文目录同步到别的设备上。
[ -f "$NEWMOUNT/.fseventsd/no_log" ] && ok "新 vault 自带 .fseventsd/no_log" || bad "缺少 .fseventsd/no_log"

for f in "$SAMPLES"/*; do
  n="$(basename "$f")"
  cp "$f" "$NEWMOUNT/$n" || bad "写入 $n 到新 vault 失败"
done
ok "已向新 vault 写入 ${#NAMES[@]} 个文件"
# 卷不支持 xattr 时，内核会给每个文件生成一个 4 KiB 的 `._名字` AppleDouble
# 边车文件来代存 —— 而 macOS 14+ 给每个新文件都自动挂 com.apple.provenance，
# 所以一旦退化，这里必然冒出 5 个垃圾文件。
dots=$(ls -A "$NEWMOUNT" | grep -c '^\._' || true)
[ "$dots" = "0" ] && ok "没有 AppleDouble ._ 边车文件" || bad "出现了 $dots 个 ._ 边车文件（xattr 支持退化了）"
for n in "${NAMES[@]}"; do
  src=$(shasum -a 256 "$SAMPLES/$n"  | awk '{print $1}')
  dst=$(shasum -a 256 "$NEWMOUNT/$n" | awk '{print $1}')
  cmp_hash "$n  新 vault 内 SHA256 一致" "$src" "$dst"
done

step "13.5 扩展属性（xattr）"
xf="$NEWMOUNT/xattr-probe.txt"; printf 'probe\n' > "$xf"
xattr -w com.apple.metadata:kMDItemWhereFroms 'https://secret.example.com/report.pdf' "$xf" 2>/dev/null \
  && ok "可以写入 xattr" || bad "写入 xattr 失败"
[ "$(xattr -p com.apple.metadata:kMDItemWhereFroms "$xf" 2>/dev/null)" = "https://secret.example.com/report.pdf" ] \
  && ok "xattr 读回一致" || bad "xattr 读回不一致"
[ -e "$NEWMOUNT/._xattr-probe.txt" ] && bad "写 xattr 触发了 ._ 边车文件" || ok "写 xattr 没有触发 ._ 边车文件"

# 密文侧必须既看不到属性名也看不到属性值
xattr -w com.apple.test.plain 'v' "$xf" 2>/dev/null
cname=$( "$APP" umount "$NEWMOUNT" >/dev/null 2>&1; ls "$NEWCIPHER" | grep -vE '^gocryptfs' | head -20 )
leak=0
for c in $cname; do
  names=$(xattr "$NEWCIPHER/$c" 2>/dev/null)
  echo "$names" | grep -qE 'kMDItem|WhereFroms|com\.apple\.test\.plain' && { bad "密文侧 xattr 名字是明文: $c"; leak=1; }
  for a in $names; do
    case "$a" in user.gocryptfs.*)
      xattr -p "$a" "$NEWCIPHER/$c" 2>/dev/null | grep -q 'secret.example.com' && { bad "密文侧 xattr 值是明文"; leak=1; };;
    esac
  done
done
[ "$leak" = "0" ] && ok "密文侧 xattr 的名字与值都已加密"

if mount_vault "$NEWCIPHER" "$NEWMOUNT" "$NEWPASSWORD"; then
  [ "$(xattr -p com.apple.metadata:kMDItemWhereFroms "$xf" 2>/dev/null)" = "https://secret.example.com/report.pdf" ] \
    && ok "xattr 跨卸载/重挂载保持不变" || bad "xattr 在重挂载后丢失"
else
  bad "xattr 段重新挂载失败"
fi
rm -f "$xf"

# fseventsd 在有文件活动之后也不该写出日志
for i in 1 2 3; do echo churn > "$NEWMOUNT/churn-$i.txt"; done; sleep 2
logs=$(ls -A "$NEWMOUNT/.fseventsd" 2>/dev/null | grep -v '^no_log$' | wc -l | tr -d ' ')
[ "$logs" = "0" ] && ok "fseventsd 没有往卷里写日志" || bad "fseventsd 写了 $logs 个日志文件"
rm -f "$NEWMOUNT"/churn-*.txt

step "13.6 特殊字符文件名与深层目录（中文、空格、Emoji）"
spec_dir="$NEWMOUNT/绝密 目录 (2026) 📁/子目录 Sub"
mkdir -p "$spec_dir" || bad "创建包含中文与Emoji的目录失败"
spec_file="$spec_dir/测试 报告 📊.txt"
echo "Unicode emoji content 🔐" > "$spec_file" || bad "写入特殊字符文件失败"
[ -f "$spec_file" ] && ok "特殊字符文件写入成功" || bad "特殊字符文件不存在"
content=$(cat "$spec_file")
[ "$content" = "Unicode emoji content 🔐" ] && ok "特殊字符文件读回内容一致" || bad "特殊字符文件读回内容不匹配"

step "13.7 深层目录重命名"
mv "$NEWMOUNT/绝密 目录 (2026) 📁" "$NEWMOUNT/已归档 目录 📦" || bad "重命名包含特殊字符的目录失败"
renamed_file="$NEWMOUNT/已归档 目录 📦/子目录 Sub/测试 报告 📊.txt"
[ -f "$renamed_file" ] && ok "重命名后深层文件路径存在" || bad "重命名后深层文件丢失"
content_after=$(cat "$renamed_file")
[ "$content_after" = "Unicode emoji content 🔐" ] && ok "重命名后深层文件内容一致" || bad "重命名后深层文件内容损坏"
rm -rf "$NEWMOUNT/已归档 目录 📦"

step "14. 卸载新 vault 并检查密文落盘"
"$APP" umount "$NEWMOUNT" >/dev/null 2>&1 && ok "新 vault 卸载成功" || bad "新 vault 卸载失败"
mount | grep -q " $NEWMOUNT " && bad "新 vault 卸载后仍在 mount 表中" || ok "新 vault 已从 mount 表移除"
leak=0
for n in "${NAMES[@]}"; do
  if ls "$NEWCIPHER" | grep -qF "$n"; then bad "新 vault 密文目录泄漏明文文件名: $n"; leak=1; fi
done
[ "$leak" = "0" ] && ok "新 vault 密文目录无明文文件名泄漏"
direct_mount_must_fail "新 vault 卸载后凭据已清除" "$NEWCIPHER"

step "15. 重新挂载新 vault 回读（持久化）"
if mount_vault "$NEWCIPHER" "$NEWMOUNT" "$NEWPASSWORD"; then ok "新 vault 重新挂载成功"; else bad "新 vault 重新挂载失败"; exit 1; fi
for n in "${NAMES[@]}"; do
  src=$(shasum -a 256 "$SAMPLES/$n"  | awk '{print $1}')
  dst=$(shasum -a 256 "$NEWMOUNT/$n" | awk '{print $1}')
  cmp_hash "$n  新 vault 重挂载后仍一致" "$src" "$dst"
done
# PDF 走一遍 QuickLook，确认新建的卷同样能被系统组件正常解析
qldir=$(mktemp -d); qlmanage -t -s 256 -o "$qldir" "$NEWMOUNT/sample.pdf" >/dev/null 2>&1
ls "$qldir"/*.png >/dev/null 2>&1 && ok "新 vault 内 sample.pdf QuickLook 渲染成功" || bad "新 vault 内 sample.pdf QuickLook 渲染失败"
rm -rf "$qldir"

step "15.5 读写模式下的完整 CRUD 验收"
# Create
printf "initial content" > "$NEWMOUNT/crud-file.txt"
mkdir "$NEWMOUNT/crud-sub"
printf "sub content" > "$NEWMOUNT/crud-sub/nested.txt"
[ -f "$NEWMOUNT/crud-file.txt" ] && [ -d "$NEWMOUNT/crud-sub" ] && [ -f "$NEWMOUNT/crud-sub/nested.txt" ] \
  && ok "读写卷下 CRUD [Create] 创建文件与目录成功" || bad "读写卷下 CRUD [Create] 失败"

# Read
content1="$(cat "$NEWMOUNT/crud-file.txt" 2>/dev/null)"
content2="$(cat "$NEWMOUNT/crud-sub/nested.txt" 2>/dev/null)"
[ "$content1" = "initial content" ] && [ "$content2" = "sub content" ] \
  && ok "读写卷下 CRUD [Read] 读取文件与嵌套内容准确" || bad "读写卷下 CRUD [Read] 失败"

# Update
printf " appended" >> "$NEWMOUNT/crud-file.txt"
[ "$(cat "$NEWMOUNT/crud-file.txt" 2>/dev/null)" = "initial content appended" ] \
  && ok "读写卷下 CRUD [Update] 既有文件追加修改成功" || bad "读写卷下 CRUD [Update] 追加修改失败"

mv "$NEWMOUNT/crud-file.txt" "$NEWMOUNT/crud-file-renamed.txt"
[ -f "$NEWMOUNT/crud-file-renamed.txt" ] && [ ! -f "$NEWMOUNT/crud-file.txt" ] \
  && ok "读写卷下 CRUD [Update] 文件重命名成功" || bad "读写卷下 CRUD [Update] 文件重命名失败"

mv "$NEWMOUNT/crud-sub" "$NEWMOUNT/crud-sub-renamed"
[ -f "$NEWMOUNT/crud-sub-renamed/nested.txt" ] && [ ! -d "$NEWMOUNT/crud-sub" ] \
  && ok "读写卷下 CRUD [Update] 目录重命名成功" || bad "读写卷下 CRUD [Update] 目录重命名失败"

chmod 600 "$NEWMOUNT/crud-file-renamed.txt" 2>/dev/null \
  && ok "读写卷下 CRUD [Update] 属性 (chmod) 修改成功" || bad "读写卷下 CRUD [Update] 属性修改失败"

# Delete
rm -f "$NEWMOUNT/crud-file-renamed.txt"
rm -rf "$NEWMOUNT/crud-sub-renamed"
[ ! -e "$NEWMOUNT/crud-file-renamed.txt" ] && [ ! -e "$NEWMOUNT/crud-sub-renamed" ] \
  && ok "读写卷下 CRUD [Delete] 删除文件与目录成功" || bad "读写卷下 CRUD [Delete] 失败"

step "16. 收尾卸载新 vault"
"$APP" umount "$NEWMOUNT" >/dev/null 2>&1 && ok "新 vault 卸载成功" || bad "新 vault 卸载失败"

step "17. 只读模式挂载 (Read-Only Mount)、_READ_ONLY 后缀与 CRUD 拦截验收"
ROMOUNT="${NEWMOUNT}_READ_ONLY"
if printf '%s\n' "$NEWPASSWORD" | "$APP" mount "$NEWCIPHER" "$NEWMOUNT" --readonly --password-stdin >/dev/null 2>&1; then
  ok "只读模式挂载命令执行成功"
else
  bad "只读模式挂载命令执行失败"
fi

if mount | grep -q " $ROMOUNT "; then
  ok "只读挂载点自动附加 _READ_ONLY 后缀 ($ROMOUNT)"
else
  bad "未在预期的 _READ_ONLY 挂载点找到卷: $(mount | grep gocryptfs || true)"
fi

VOL_NAME="$(swift -e 'import Foundation; let url = URL(fileURLWithPath: "'"$ROMOUNT"'"); print((try? url.resourceValues(forKeys: [.volumeNameKey]))?.volumeName ?? "")')"
if [[ "$VOL_NAME" == *"_READ_ONLY"* ]]; then
  ok "Finder 宗卷显示名称包含 _READ_ONLY 后缀 ($VOL_NAME)"
else
  bad "Finder 宗卷显示名称未带 _READ_ONLY 后缀 (实际为: $VOL_NAME)"
fi

# ── CRUD [Read]: 允许 ──
if [ -f "$ROMOUNT/sample.txt" ]; then
  ok "只读卷下 CRUD [Read] 文件正常读取"
else
  bad "只读卷下 CRUD [Read] 文件读取失败"
fi

if [ -d "$ROMOUNT" ] && [ "$(ls -A "$ROMOUNT" | wc -l)" -gt 0 ]; then
  ok "只读卷下 CRUD [Read] 目录正常遍历"
else
  bad "只读卷下 CRUD [Read] 目录遍历失败"
fi

# ── CRUD [Create]: 拦截 ──
if touch "$ROMOUNT/create-blocked.txt" >/dev/null 2>&1; then
  bad "只读卷下 CRUD [Create] touch 意外成功"
  rm -f "$ROMOUNT/create-blocked.txt"
else
  ok "只读卷下 CRUD [Create] 禁止 touch 新建文件 (拦截成功)"
fi

if mkdir "$ROMOUNT/create-dir-blocked" >/dev/null 2>&1; then
  bad "只读卷下 CRUD [Create] mkdir 意外成功"
  rmdir "$ROMOUNT/create-dir-blocked"
else
  ok "只读卷下 CRUD [Create] 禁止 mkdir 创建目录 (拦截成功)"
fi

# ── CRUD [Update]: 拦截 ──
if ( echo "append-attack" >> "$ROMOUNT/sample.txt" ) >/dev/null 2>&1; then
  bad "只读卷下 CRUD [Update] 追加修改意外成功"
else
  ok "只读卷下 CRUD [Update] 禁止追加写入既有文件 (拦截成功)"
fi

if mv "$ROMOUNT/sample.txt" "$ROMOUNT/sample-renamed.txt" >/dev/null 2>&1; then
  bad "只读卷下 CRUD [Update] mv 重命名意外成功"
else
  ok "只读卷下 CRUD [Update] 禁止重命名文件 (拦截成功)"
fi

if chmod 777 "$ROMOUNT/sample.txt" >/dev/null 2>&1; then
  bad "只读卷下 CRUD [Update] chmod 属性修改意外成功"
else
  ok "只读卷下 CRUD [Update] 禁止修改文件属性 (拦截成功)"
fi

# ── CRUD [Delete]: 拦截 ──
if rm -f "$ROMOUNT/sample.txt" >/dev/null 2>&1; then
  bad "只读卷下 CRUD [Delete] rm 意外成功"
else
  ok "只读卷下 CRUD [Delete] 禁止删除既有文件 (拦截成功)"
fi

# ── 卸载与清理 ──
"$APP" umount "$ROMOUNT" >/dev/null 2>&1 && ok "只读卷卸载成功" || bad "只读卷卸载失败"
mount | grep -q " $ROMOUNT " && bad "只读卷卸载后仍在 mount 表中" || ok "只读卷已从 mount 表移除"

if [ ! -d "$ROMOUNT" ]; then
  ok "卸载后自动清理了 _READ_ONLY 临时空目录"
else
  bad "卸载后未清理 _READ_ONLY 临时目录"
fi

printf '\n\033[1m═══ 结果: %d 通过, %d 失败 ═══\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
