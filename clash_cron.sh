#!/usr/bin/env bash

# 安全选项
set -Eeuo pipefail
IFS=$'\n\t'

# ===================== 可配置参数（可用环境变量覆盖） =====================
SCRIPT_DIR="/home/shavingha/tools"
LOG_DIR="${LOG_DIR:-${SCRIPT_DIR}/logs}"
CLASH_RUN_LOG="${CLASH_RUN_LOG:-${LOG_DIR}/clash_run.log}"

# Clash 启动相关（按需修改）
CLASH_WORKDIR="${CLASH_WORKDIR:-${SCRIPT_DIR}}"
CLASH_CMD="${CLASH_CMD:-${CLASH_WORKDIR}/clash}"
CLASH_CONFIG="${CLASH_CONFIG:-}"   # 例如: /home/shavingha/.config/clash/config.yaml
CLASH_HTTP_PORT="${CLASH_HTTP_PORT:-7890}"

# 订阅脚本及地址（按需修改）
PYTHON_BIN="${PYTHON_BIN:-python3}"
SSR_SCRIPT="${SSR_SCRIPT:-${SCRIPT_DIR}/ssr.py}"
SUB_URL_PRIMARY="${SUB_URL_PRIMARY:-https://jmssub.net/members/getsub.php?service=731341&id=35900538-d931-4000-88ae-4751e9784470}"
SUB_URL_FALLBACK="${SUB_URL_FALLBACK:-https://jjsubmarines.com/members/getsub.php?service=731341&id=35900538-d931-4000-88ae-4751e9784470}"

# 连通性检测目标
TEST_URL="${TEST_URL:-https://www.google.com.hk/generate_204}"
TEST_TIMEOUT="${TEST_TIMEOUT:-8}"

# ===================== 日志与工具函数 =====================
mkdir -p "${LOG_DIR}"

log() {
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${ts}] INFO: $*"
}

err() {
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${ts}] ERROR: $*" >&2
}

run_cmd() {
    # 运行命令并记录成功/失败
    local desc="$1"; shift
    log "开始: ${desc}"
    if "$@"; then
        log "完成: ${desc}"
        return 0
    else
        err "失败: ${desc}"
        return 1
    fi
}

# ===================== 功能函数 =====================
resolve_clash_cmd() {
    # 只使用当前工作目录下的 ./clash
    local candidate="${CLASH_WORKDIR}/clash"
    if [[ ! -x "${candidate}" ]]; then
        return 1
    fi
    local abs
    abs="$(readlink -f "${candidate}" 2>/dev/null || true)"
    if [[ -n "${abs}" ]]; then
        printf '%s' "${abs}"
    else
        printf '%s' "${candidate}"
    fi
}
check_connectivity_via_clash() {
    # 通过 Clash 本地代理检测可达性
    local proxy="http://127.0.0.1:${CLASH_HTTP_PORT}"
    curl --silent --show-error --max-time "${TEST_TIMEOUT}" \
         --proxy "${proxy}" --proxy-insecure \
         -o /dev/null -w '%{http_code}' "${TEST_URL}" || return 1
}

refresh_subscription() {
    # 调用 ssr.py 刷新订阅，主备地址
    if [[ ! -x "${SSR_SCRIPT}" && ! -f "${SSR_SCRIPT}" ]]; then
        err "未找到订阅脚本: ${SSR_SCRIPT}"
        return 1
    fi

    log "尝试主订阅地址刷新"
    if "${PYTHON_BIN}" "${SSR_SCRIPT}" "${SUB_URL_PRIMARY}"; then
        log "主订阅刷新成功"
        return 0
    fi

    err "主订阅刷新失败，尝试备用订阅地址"
    if "${PYTHON_BIN}" "${SSR_SCRIPT}" "${SUB_URL_FALLBACK}"; then
        log "备用订阅刷新成功"
        return 0
    else
        err "备用订阅刷新失败"
        return 1
    fi
}

stop_clash() {
    local pid_file="${LOG_DIR}/clash.pid"
    local resolved
    resolved="$(resolve_clash_cmd || true)"

    # 1) 优先通过 PID 文件停止
    if [[ -f "${pid_file}" ]]; then
        local pid
        pid="$(cat "${pid_file}" 2>/dev/null || true)"
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            log "通过 PID 文件停止 Clash: ${pid}"
            kill "${pid}" 2>/dev/null || true
            sleep 1
        fi
    fi

    # 2) 清理残留：按完整命令行匹配已解析路径
    if [[ -n "${resolved}" ]]; then
        local pids
        pids="$(pgrep -f "${resolved}" || true)"
        if [[ -n "${pids// /}" ]]; then
            log "检测到 Clash 残留进程: ${pids}，准备结束"
            kill ${pids} 2>/dev/null || true
            sleep 1
            local still
            still="$(pgrep -f "${resolved}" || true)"
            if [[ -n "${still// /}" ]]; then
                err "强制结束残留 Clash 进程: ${still}"
                kill -9 ${still} 2>/dev/null || true
                sleep 1
            fi
        fi
    fi
}

start_clash_background() {
    : > "${CLASH_RUN_LOG}"
    local resolved
    if ! resolved="$(resolve_clash_cmd)"; then
        err "未能找到 clash 可执行文件，请确认存在 ${CLASH_WORKDIR}/clash 且有执行权限"
        return 1
    fi

    # 自动探测配置文件（如未设置）
    local effective_config="${CLASH_CONFIG}"
    if [[ -z "${effective_config}" ]]; then
        if [[ -f "${CLASH_WORKDIR}/config.yaml" ]]; then
            effective_config="${CLASH_WORKDIR}/config.yaml"
        elif [[ -f "${CLASH_WORKDIR}/clash_config.yaml" ]]; then
            effective_config="${CLASH_WORKDIR}/clash_config.yaml"
        fi
    fi

    log "使用 Clash 可执行文件: ${resolved}"
    if [[ -n "${effective_config}" ]]; then
        log "使用配置文件: ${effective_config}"
    fi

    local cmd=("${resolved}")
    if [[ -n "${effective_config}" ]]; then
        cmd+=("-f" "${effective_config}")
    fi

    local pid_file="${LOG_DIR}/clash.pid"
    (
        cd "${CLASH_WORKDIR}" || exit 1
        nohup "${cmd[@]}" >>"${CLASH_RUN_LOG}" 2>&1 &
        local child=$!
        echo "${child}" > "${pid_file}"
        disown || true
    )
    sleep 1
    if [[ -f "${pid_file}" ]]; then
        local child
        child="$(cat "${pid_file}")"
        if [[ -n "${child}" ]] && kill -0 "${child}" 2>/dev/null; then
            log "Clash 已后台启动，PID: ${child}（日志: ${CLASH_RUN_LOG}）"
            return 0
        fi
    fi
    err "Clash 启动失败，请检查 ${CLASH_RUN_LOG}"
    return 1
}

log_clash_status_snapshot() {
    log "Clash 运行状态快照:"
    local resolved
    resolved="$(resolve_clash_cmd || true)"
    if [[ -n "${resolved}" ]]; then
        pgrep -a -f "${resolved}" || true
    fi
    # 端口监听情况
    if command -v ss >/dev/null 2>&1; then
        ss -lntp | grep ":${CLASH_HTTP_PORT} " || true
    elif command -v netstat >/dev/null 2>&1; then
        netstat -lntp | grep ":${CLASH_HTTP_PORT} " || true
    fi
}

# ===================== 主流程 =====================
log "===================== clash_cron 开始 ====================="

# 1) 通过 Clash 代理检测 Google 可达
log "检测通过 Clash 代理访问: ${TEST_URL}"
http_code="$(check_connectivity_via_clash || true)"
if [[ "${http_code:-}" == "204" || "${http_code:-}" == "200" ]]; then
    log "连通性正常 (HTTP ${http_code}), 不需要刷新订阅/重启 Clash"
    log_clash_status_snapshot
    log "===================== clash_cron 结束(OK) ====================="
    exit 0
else
    err "连通性异常 (返回: ${http_code:-N/A}), 将刷新订阅并重启 Clash"
fi

# 2) 刷新订阅（主备）
if ! refresh_subscription; then
    err "订阅刷新全部失败，仍将尝试重启 Clash"
fi

# 3) 重启 Clash（后台运行并 disown）
stop_clash
if start_clash_background; then
    log_clash_status_snapshot
    # 4) 重启后二次连通性验证
    sleep 2
    http_code2="$(check_connectivity_via_clash || true)"
    if [[ "${http_code2:-}" == "204" || "${http_code2:-}" == "200" ]]; then
        log "重启后连通性正常 (HTTP ${http_code2})"
        log "===================== clash_cron 结束(OK) ====================="
        exit 0
    else
        err "重启后连通性仍异常 (返回: ${http_code2:-N/A})，请检查 ${CLASH_RUN_LOG}"
        log "===================== clash_cron 结束(FAILED) ====================="
        exit 1
    fi
else
    err "Clash 启动失败"
    log "===================== clash_cron 结束(FAILED) ====================="
    exit 1
fi


