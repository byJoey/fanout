#!/usr/bin/env bash
# fanout 安装脚本：装 fanout + sing-box、装服务（systemd 或 OpenRC）、开机自启。
#
# Alpine 默认不带 bash，先装再跑：
#   apk add bash && bash <(curl -fsSL .../install.sh)

set -euo pipefail

WEB_PORT="${WEB_PORT:-8899}"
WORK_DIR="${WORK_DIR:-/var/lib/fanout}"
BIN=/usr/local/bin/fanout

if [[ $EUID -ne 0 ]]; then
  echo "需要 root 权限（要安装服务和程序）" >&2
  exit 1
fi

# ── init 系统抽象：systemd 与 OpenRC 两套 ────────────────
INIT_SYS=""
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  INIT_SYS=systemd
elif command -v rc-service >/dev/null 2>&1; then
  INIT_SYS=openrc
else
  echo "不认识的 init 系统（需要 systemd 或 OpenRC）" >&2
  exit 1
fi

svc_install() {
  if [[ "$INIT_SYS" == systemd ]]; then
    sed "s#-web 8899#-web ${WEB_PORT}#; s#-dir /var/lib/fanout#-dir ${WORK_DIR}#" fanout.service \
      > /etc/systemd/system/fanout.service
    systemctl daemon-reload
  else
    # OpenRC 没有 systemd 那套单元文件，直接写 init script。
    # supervise-daemon 负责守护与重启，等价于 Restart=on-failure。
    cat > /etc/init.d/fanout <<INITEOF
#!/sbin/openrc-run
name="fanout"
description="fanout - VPN Gate 出口扇出网关"
command="${BIN}"
command_args="-web ${WEB_PORT} -dir ${WORK_DIR}"
command_background=true
pidfile="/run/fanout.pid"
output_log="/var/log/fanout.log"
error_log="/var/log/fanout.log"
respawn_delay=5
respawn_max=0
supervisor=supervise-daemon
depend() { need net; after firewall; }
INITEOF
    chmod +x /etc/init.d/fanout
  fi
}

svc_enable_start() {
  if [[ "$INIT_SYS" == systemd ]]; then
    systemctl enable --now fanout
  else
    rc-update add fanout default >/dev/null 2>&1 || true
    rc-service fanout restart
  fi
}

svc_is_active() {
  if [[ "$INIT_SYS" == systemd ]]; then
    systemctl is-active --quiet fanout
  else
    rc-service fanout status >/dev/null 2>&1
  fi
}

svc_logs_hint() {
  [[ "$INIT_SYS" == systemd ]] && echo "journalctl -u fanout -n 30" || echo "cat /var/log/fanout.log"
}

echo "[1/5] 检查依赖"

# 同一个命令在各发行版里的包名并不一致，按包管理器分别给出。
pkg_for() {
  local cmd="$1" mgr="$2"
  case "$cmd" in
    curl)     echo curl ;;
    tar)      echo tar ;;
  esac
}

detect_mgr() {
  for m in apt-get dnf yum pacman apk zypper; do
    command -v "$m" >/dev/null && { echo "$m"; return; }
  done
  echo ""
}

install_pkgs() {
  local mgr="$1"; shift
  case "$mgr" in
    apt-get)
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
      ;;
    dnf)    dnf install -y -q "$@" ;;
    yum)    yum install -y -q "$@" ;;
    pacman) pacman -Sy --noconfirm --needed "$@" ;;
    apk)    apk add --no-cache "$@" ;;
    zypper) zypper --non-interactive install -y "$@" ;;
  esac
}

MGR=$(detect_mgr)
need_cmd=()
for c in curl tar; do
  command -v "$c" >/dev/null || need_cmd+=("$c")
done

if [[ ${#need_cmd[@]} -gt 0 ]]; then
  echo "      缺少: ${need_cmd[*]}"
  if [[ -z "$MGR" ]]; then
    echo "      不认识的包管理器，请手动安装后重试" >&2
    exit 1
  fi
  pkgs=()
  for c in "${need_cmd[@]}"; do pkgs+=("$(pkg_for "$c" "$MGR")"); done
  echo "      安装: ${pkgs[*]}"
  install_pkgs "$MGR" "${pkgs[@]}" || {
    echo "      自动安装失败，请手动安装: ${pkgs[*]}" >&2
    exit 1
  }
fi

echo "[2/5] 获取程序"
REPO="${REPO:-byJoey/fanout}"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) echo "      不支持的架构: $ARCH" >&2; exit 1 ;;
esac

if [[ -f main.go ]] && command -v go >/dev/null; then
  echo "      从源码编译"
  go build -trimpath -ldflags "-s -w" -o "$BIN" .
else
  echo "      下载预编译版本 (${GOARCH})"
  TMP=$(mktemp -d)
  URL="https://github.com/${REPO}/releases/latest/download/fanout-linux-${GOARCH}.tar.gz"
  if ! curl -fsSL "$URL" -o "$TMP/f.tar.gz"; then
    echo "      下载失败: $URL" >&2
    echo "      也可以 clone 仓库后在源码目录运行本脚本" >&2
    exit 1
  fi
  tar xzf "$TMP/f.tar.gz" -C "$TMP"
  install -m 755 "$TMP/fanout" "$BIN"
  [[ -f fanout.service ]] || cp "$TMP/fanout.service" .
  [[ -f "$TMP/f.sh" ]] && install -m 755 "$TMP/f.sh" /usr/local/bin/f
  rm -rf "$TMP"
fi

SINGBOX_VERSION="${SINGBOX_VERSION:-latest}"
if [[ "$SINGBOX_VERSION" == "latest" ]]; then
  SINGBOX_TAG_URL=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    https://github.com/SagerNet/sing-box/releases/latest || true)
  SINGBOX_VERSION=${SINGBOX_TAG_URL##*/}
  SINGBOX_VERSION=${SINGBOX_VERSION#v}
fi
[[ "$SINGBOX_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || {
  echo "      无法确定 sing-box 版本，请设置 SINGBOX_VERSION，例如 1.14.0-alpha.50" >&2
  exit 1
}
echo "[3/5] 准备 sing-box ${SINGBOX_VERSION}（运行时要求 >= 1.14）"
mkdir -p "${WORK_DIR}/bin"
CURRENT_SINGBOX=""
if [[ -x "${WORK_DIR}/bin/sing-box" ]]; then
  CURRENT_SINGBOX=$("${WORK_DIR}/bin/sing-box" version 2>/dev/null | head -1 || true)
fi
CURRENT_VERSION=$(sed -n 's/^sing-box version \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' <<<"$CURRENT_SINGBOX")
if [[ "$CURRENT_VERSION" =~ ^1\.(1[4-9]|[2-9][0-9])$ || "$CURRENT_VERSION" =~ ^[2-9][0-9]*\. ]] && \
   [[ "$CURRENT_SINGBOX" == *with_openvpn* && "$CURRENT_SINGBOX" == *with_gvisor* ]]; then
  echo "      已有 ${CURRENT_SINGBOX}"
else
  echo "      下载 sing-box"
  ST=$(mktemp -d)
  SINGBOX_ASSET="sing-box-${SINGBOX_VERSION}-linux-${GOARCH}.tar.gz"
  SINGBOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${SINGBOX_ASSET}"
  if ! curl -fsSL "$SINGBOX_URL" -o "$ST/sing-box.tar.gz"; then
    echo "      下载失败: $SINGBOX_URL" >&2
    exit 1
  fi
  case "$GOARCH" in
    amd64) SINGBOX_SHA256=b2af50118c457e13e9e6deeb1ee07e609d8862deb2568ea267b941e594234ca8 ;;
    arm64) SINGBOX_SHA256=18216accfbe05482fff35af4b5fa5f2b8c6a655c9675f6482e3846da34ca18db ;;
  esac
  if [[ -n "${SINGBOX_SHA256:-}" ]] && command -v sha256sum >/dev/null 2>&1; then
    SINGBOX_ACTUAL=$(sha256sum "$ST/sing-box.tar.gz")
    SINGBOX_ACTUAL=${SINGBOX_ACTUAL%% *}
    [[ "$SINGBOX_ACTUAL" == "$SINGBOX_SHA256" ]] || {
      echo "      sing-box 压缩包校验失败" >&2
      exit 1
    }
  fi
  tar xzf "$ST/sing-box.tar.gz" -C "$ST"
  SB_BIN=$(find "$ST" -type f -name sing-box -perm -u+x | head -1)
  [[ -n "$SB_BIN" ]] || { echo "      sing-box 解压失败" >&2; exit 1; }
  install -m 755 "$SB_BIN" "${WORK_DIR}/bin/sing-box"
  echo "      $("${WORK_DIR}/bin/sing-box" version 2>/dev/null | head -1)"
  rm -rf "$ST"
fi
SINGBOX_INFO=$("${WORK_DIR}/bin/sing-box" version 2>/dev/null)
[[ "$SINGBOX_INFO" == *with_openvpn* && "$SINGBOX_INFO" == *with_gvisor* ]] || {
  echo "      sing-box 缺少 with_openvpn 或 with_gvisor 构建标签" >&2
  exit 1
}

echo "[4/5] 安装服务"
# 管理菜单
if [[ -f f.sh ]]; then
  install -m 755 f.sh /usr/local/bin/f
elif [[ -n "${TMP:-}" && -f "${TMP}/f.sh" ]]; then
  install -m 755 "${TMP}/f.sh" /usr/local/bin/f
else
  curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/f.sh" -o /usr/local/bin/f \
    && chmod 755 /usr/local/bin/f
fi
mkdir -p "$WORK_DIR"
chmod 700 "$WORK_DIR"
svc_install
svc_enable_start

echo "[5/5] 就绪"
sleep 3
svc_is_active && echo "      服务运行中（${INIT_SYS}）" || {
  echo "      服务启动失败，看 $(svc_logs_hint)" >&2
  exit 1
}

# 口令与访问路径由 fanout 首次启动时生成，等它写出来
for _ in $(seq 1 10); do
  [[ -s "${WORK_DIR}/password" && -s "${WORK_DIR}/basepath" ]] && break
  sleep 1
done

IP=$(curl -s --max-time 8 http://api.ipify.org || echo "<本机IP>")
BP=$(cat "${WORK_DIR}/basepath" 2>/dev/null || true)
echo
echo "  管理界面  http://${IP}:${WEB_PORT}/${BP}/"
echo "  访问口令  $(cat "${WORK_DIR}/password" 2>/dev/null || echo "见 ${WORK_DIR}/password")"
echo
echo "  路径和口令都是随机生成的，也可以随时查看："
echo "    cat ${WORK_DIR}/basepath"
echo "    cat ${WORK_DIR}/password"
echo
echo "  输入 f 打开管理菜单"
echo
echo "  ────────────────────────────────"
echo "  交流群  https://t.me/+ft-zI76oovgwNmRh"
echo "  油管    https://youtube.com/@joeyblog"
echo "  博客    https://joeyblog.net"
echo "  项目    https://github.com/byJoey/fanout"
echo
