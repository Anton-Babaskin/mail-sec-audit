#!/usr/bin/env bash
# mail-sec-audit.sh — универсальный read-only security-аудит Linux-почтового сервера
# Поддержка: Postfix / Exim / Sendmail / OpenSMTPD, Dovecot / Courier,
# UFW / firewalld / nftables / iptables, Fail2ban, systemd/journald.
#
# Запуск:
#   sudo bash mail-sec-audit.sh
#   sudo bash mail-sec-audit.sh --days 7 --hostname mail.example.com --domain example.com
#   sudo MAIL_AUDIT_ALLOWED_PORTS="10050 9100" bash mail-sec-audit.sh
#
# Exit codes:
#   0 — критических замечаний и предупреждений нет
#   1 — есть предупреждения
#   2 — есть критические замечания

set -uo pipefail
umask 077
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export LC_ALL=C

SCRIPT_VERSION="2.3.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DAYS=7
MAIL_TOP=20
MAIL_HOST=""
MAIL_DOMAIN=""
DKIM_SELECTOR=""
FROM_DATE=""
TO_DATE=""
AUDIT_FROM=""
AUDIT_TO=""
PLATFORM_OVERRIDE="auto"
MAIL_PLATFORM="generic"
PLATFORM_VERSION=""
MAILCOW_POSTFIX_CONTAINER=""
MAILCOW_DOVECOT_CONTAINER=""
OUTPUT_FORMAT="text"
REDACT=0
APPEND_REPORT=0
DEEP=0
NO_COLOR=0
INTERACTIVE=0
VERBOSE=0
REPORT_FILE=""
WARNINGS=0
CRITICALS=0
PASSES=0
INFOS=0
SECTION_NO=0
MTA="none"
IMAP_SERVER="none"
MAIL_AUDIT_ALLOWED_PORTS="${MAIL_AUDIT_ALLOWED_PORTS:-}"

usage() {
  cat <<'USAGE'
Использование:
  sudo bash mail-sec-audit.sh [опции]

Опции:
  --days N              Период анализа journal/log, по умолчанию 7 дней
  --mail-top N          Сколько доменов показывать в почтовой статистике, по умолчанию 20
  --from YYYY-MM-DD     Начало периода почтовой статистики, включительно
  --to YYYY-MM-DD       Конец периода почтовой статистики, включительно
  --hostname FQDN       Основное имя почтового сервера для TLS-проверок
  --domain DOMAIN       Почтовый домен для MX/SPF/DMARC-проверок
  --dkim-selector SEL   DKIM-селектор для DNS-проверки
  --platform NAME       auto, generic, mailcow, iredmail или mailinabox
  --format FORMAT       Формат основного вывода: text или json
  --redact              Скрывать email-адреса и IP в выводе и отчёте
  --deep                Дополнительные, более тяжёлые проверки
  --report FILE         Сохранить отчёт в новый файл с правами 0600
  --append-report FILE  Дописать отчёт в существующий безопасный файл
  --interactive         После аудита открыть безопасное меню Fail2ban
  --verbose             Показывать полный сырой вывод firewall/listeners
  --no-color            Отключить ANSI-цвета
  --version             Показать версию и выйти
  -h, --help            Показать справку

Дополнительные разрешённые публичные порты:
  MAIL_AUDIT_ALLOWED_PORTS="10050 9100" sudo bash mail-sec-audit.sh

По умолчанию скрипт полностью read-only. Изменения возможны только в явно включённом
режиме --interactive и только после подтверждения каждой операции.
USAGE
}

argument_error() {
  printf 'Ошибка: %s\n' "$1" >&2
  exit 64
}

require_option_value() {
  local option="$1"
  if (( $# < 2 )) || [[ -z "$2" || "$2" == -* ]]; then
    argument_error "$option требует значение"
  fi
}

validate_dns_argument() {
  local option="$1" value="$2"
  if (( ${#value} > 253 )) || [[ ! "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]]; then
    argument_error "$option содержит недопустимое имя: $value"
  fi
}

validate_allowed_ports() {
  local port
  local -a allowed_ports=()
  read -r -a allowed_ports <<<"$MAIL_AUDIT_ALLOWED_PORTS"
  for port in "${allowed_ports[@]}"; do
    if [[ ! "$port" =~ ^[0-9]+$ || ${#port} -gt 5 ]] || (( 10#$port < 1 || 10#$port > 65535 )); then
      argument_error "MAIL_AUDIT_ALLOWED_PORTS содержит недопустимый порт: $port"
    fi
  done
}

validate_iso_date() {
  local option="$1" value="$2"
  if [[ ! "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] \
    || ! date -d "$value" '+%Y-%m-%d' 2>/dev/null | grep -qx "$value"; then
    argument_error "$option требует корректную дату YYYY-MM-DD"
  fi
}

while (($#)); do
  case "$1" in
    --days)
      require_option_value "$@"
      if [[ ! "$2" =~ ^[0-9]+$ || ${#2} -gt 4 ]] || (( 10#$2 < 1 || 10#$2 > 3650 )); then
        argument_error "--days требует число от 1 до 3650"
      fi
      DAYS="$2"; shift 2 ;;
    --mail-top)
      require_option_value "$@"
      if [[ ! "$2" =~ ^[0-9]+$ || ${#2} -gt 3 ]] || (( 10#$2 < 1 || 10#$2 > 100 )); then
        argument_error "--mail-top требует число от 1 до 100"
      fi
      MAIL_TOP="$2"; shift 2 ;;
    --from)
      require_option_value "$@"
      validate_iso_date "--from" "$2"
      FROM_DATE="$2"; shift 2 ;;
    --to)
      require_option_value "$@"
      validate_iso_date "--to" "$2"
      TO_DATE="$2"; shift 2 ;;
    --hostname)
      require_option_value "$@"
      validate_dns_argument "--hostname" "$2"
      MAIL_HOST="$2"; shift 2 ;;
    --domain)
      require_option_value "$@"
      validate_dns_argument "--domain" "$2"
      MAIL_DOMAIN="$2"; shift 2 ;;
    --dkim-selector)
      require_option_value "$@"
      validate_dns_argument "--dkim-selector" "$2"
      DKIM_SELECTOR="$2"; shift 2 ;;
    --platform)
      require_option_value "$@"
      case "$2" in auto|generic|mailcow|iredmail|mailinabox) ;; *) argument_error "неизвестная платформа: $2" ;; esac
      PLATFORM_OVERRIDE="$2"; shift 2 ;;
    --format)
      require_option_value "$@"
      case "$2" in text|json) ;; *) argument_error "--format поддерживает text или json" ;; esac
      OUTPUT_FORMAT="$2"; shift 2 ;;
    --redact)
      REDACT=1; shift ;;
    --deep)
      DEEP=1; shift ;;
    --report)
      require_option_value "$@"
      [[ -z "$REPORT_FILE" ]] || argument_error "--report и --append-report можно указать только один раз"
      REPORT_FILE="$2"; shift 2 ;;
    --append-report)
      require_option_value "$@"
      [[ -z "$REPORT_FILE" ]] || argument_error "--report и --append-report можно указать только один раз"
      REPORT_FILE="$2"; APPEND_REPORT=1; shift 2 ;;
    --interactive|--manage-bans)
      INTERACTIVE=1; shift ;;
    --verbose)
      VERBOSE=1; shift ;;
    --no-color)
      NO_COLOR=1; shift ;;
    --version)
      printf 'mail-sec-audit %s\n' "$SCRIPT_VERSION"; exit 0 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Неизвестная опция: $1" >&2
      usage >&2
      exit 64 ;;
  esac
done

validate_allowed_ports
if [[ "$OUTPUT_FORMAT" == "json" ]] && ! command -v python3 >/dev/null 2>&1; then
  printf 'Ошибка: --format json требует python3\n' >&2
  exit 69
fi
if [[ "$OUTPUT_FORMAT" == "json" && "$APPEND_REPORT" -eq 1 ]]; then
  argument_error "--append-report нельзя сочетать с --format json; JSON-отчёт должен быть отдельным файлом"
fi
if [[ "$OUTPUT_FORMAT" == "json" && "$INTERACTIVE" -eq 1 ]]; then
  argument_error "--interactive нельзя сочетать с --format json"
fi

if [[ -n "$TO_DATE" ]]; then
  AUDIT_TO="$TO_DATE 23:59:59"
else
  AUDIT_TO="$(date '+%Y-%m-%d %H:%M:%S')"
fi
if [[ -n "$FROM_DATE" ]]; then
  AUDIT_FROM="$FROM_DATE 00:00:00"
elif [[ -n "$TO_DATE" ]]; then
  AUDIT_FROM="$(date -d "$TO_DATE -$((DAYS - 1)) days" '+%Y-%m-%d 00:00:00')"
else
  AUDIT_FROM="$(date -d "$DAYS days ago" '+%Y-%m-%d 00:00:00')"
fi
if (( $(date -d "$AUDIT_FROM" +%s) > $(date -d "$AUDIT_TO" +%s) )); then
  argument_error "--from не может быть позже --to"
fi
DAYS=$(( ($(date -d "$AUDIT_TO" +%s) - $(date -d "$AUDIT_FROM" +%s) + 86399) / 86400 ))
(( DAYS >= 1 )) || DAYS=1

if [[ ! "${COLUMNS:-}" =~ ^[0-9]+$ ]] || (( COLUMNS < 60 || COLUMNS > 200 )); then
  COLUMNS=88
fi

TMPROOT="$(mktemp -d /tmp/mail-sec-audit.XXXXXX)" || exit 1
FINDINGS_FILE="$TMPROOT/findings.tsv"
MAIL_STATS_JSON="$TMPROOT/mail-stats.json"
: >"$FINDINGS_FILE"

# ShellCheck 0.9 reports SC2317 and 0.11 reports SC2329 for trap-only functions.
# shellcheck disable=SC2317,SC2329
cleanup() {
  if [[ -n "${TMPROOT:-}" && "$TMPROOT" == /tmp/mail-sec-audit.* && -d "$TMPROOT" && ! -L "$TMPROOT" ]]; then
    rm -rf -- "$TMPROOT"
  fi
}
trap cleanup EXIT HUP INT TERM

prepare_report_target() {
  local target="$1" parent owner
  parent="$(dirname -- "$target")"
  mkdir -p -- "$parent" 2>/dev/null || { printf 'Не удалось создать каталог отчёта: %s\n' "$parent" >&2; exit 73; }
  [[ ! -L "$target" ]] || { printf 'Отказ: путь отчёта является символической ссылкой: %s\n' "$target" >&2; exit 73; }
  if (( APPEND_REPORT == 1 )); then
    [[ -f "$target" ]] || { printf 'Для --append-report нужен существующий обычный файл: %s\n' "$target" >&2; exit 73; }
    owner="$(stat -c '%u' "$target" 2>/dev/null || true)"
    [[ "$owner" == "$EUID" ]] || { printf 'Отказ: файл отчёта принадлежит другому пользователю\n' >&2; exit 73; }
  else
    [[ ! -e "$target" ]] || { printf 'Файл уже существует; используй --append-report: %s\n' "$target" >&2; exit 73; }
    (set -o noclobber; : >"$target") 2>/dev/null \
      || { printf 'Не удалось безопасно создать отчёт: %s\n' "$target" >&2; exit 73; }
  fi
  chmod 600 -- "$target" 2>/dev/null || { printf 'Не удалось установить права 0600: %s\n' "$target" >&2; exit 73; }
}

redact_stream() {
  sed -E \
    -e 's/[[:alnum:]._%+-]+@[[:alnum:].-]+/<redacted-email>/g' \
    -e 's/([0-9]{1,3}\.){3}[0-9]{1,3}/<redacted-ip>/g' \
    -e 's/([[:xdigit:]]{0,4}:){2,7}[[:xdigit:]]{0,4}/<redacted-ipv6>/g'
}

STDOUT_WAS_TTY=0
[[ -t 1 ]] && STDOUT_WAS_TTY=1
[[ "$OUTPUT_FORMAT" == "json" ]] && NO_COLOR=1

if [[ -n "$REPORT_FILE" ]]; then
  prepare_report_target "$REPORT_FILE"
fi

if [[ "$OUTPUT_FORMAT" == "json" ]]; then
  exec 3>&1 4>&2
  exec >"$TMPROOT/human-report.txt" 2>&1
elif [[ -n "$REPORT_FILE" && "$REDACT" -eq 1 && "$APPEND_REPORT" -eq 1 ]]; then
  exec > >(redact_stream | tee -a -- "$REPORT_FILE") 2>&1
elif [[ -n "$REPORT_FILE" && "$REDACT" -eq 1 ]]; then
  exec > >(redact_stream | tee -- "$REPORT_FILE") 2>&1
elif [[ -n "$REPORT_FILE" && "$APPEND_REPORT" -eq 1 ]]; then
  exec > >(tee -a -- "$REPORT_FILE") 2>&1
elif [[ -n "$REPORT_FILE" ]]; then
  exec > >(tee -- "$REPORT_FILE") 2>&1
elif (( REDACT == 1 )); then
  exec > >(redact_stream) 2>&1
fi

if (( STDOUT_WAS_TTY == 1 && NO_COLOR == 0 )); then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[1;31m'; YELLOW=$'\033[1;33m'
  GREEN=$'\033[1;32m'; BLUE=$'\033[1;34m'; CYAN=$'\033[1;36m'
  MAGENTA=$'\033[1;35m'; WHITE=$'\033[1;37m'; RESET=$'\033[0m'
else
  BOLD=""; DIM=""; RED=""; YELLOW=""; GREEN=""; BLUE=""; CYAN=""
  MAGENTA=""; WHITE=""; RESET=""
fi

hr() { local line; printf -v line '%*s' "$COLUMNS" ''; printf '%s%s%s\n' "$DIM" "${line// /─}" "$RESET"; }
banner() {
  printf '\n%s' "$CYAN$BOLD"; hr
  printf '  MAIL SECURITY AUDIT  v%s\n' "$SCRIPT_VERSION"
  printf '  host: %-40s period: %s -> %s\n' "$MAIL_HOST" "${AUDIT_FROM%% *}" "${AUDIT_TO%% *}"
  hr; printf '%s' "$RESET"
}
section() {
  SECTION_NO=$((SECTION_NO+1))
  FINDING_SEQ=0
  case "$1" in
    "AUDIT CONTEXT") CURRENT_SECTION_CODE="CTX" ;;
    "PATCHES / REBOOT") CURRENT_SECTION_CODE="PATCH" ;;
    "MAIL PLATFORM / STACK DETECTION") CURRENT_SECTION_CODE="STACK" ;;
    "SSHD EFFECTIVE CONFIG") CURRENT_SECTION_CODE="SSH" ;;
    "LISTENING PORTS / PUBLIC BINDS") CURRENT_SECTION_CODE="NET" ;;
    "FIREWALL") CURRENT_SECTION_CODE="FW" ;;
    "BRUTE-FORCE PROTECTION") CURRENT_SECTION_CODE="BRUTE" ;;
    "AUTHENTICATION EVENTS") CURRENT_SECTION_CODE="AUTH" ;;
    "MAIL FLOW ANALYTICS") CURRENT_SECTION_CODE="FLOW" ;;
    "MTA / RELAY CONFIGURATION") CURRENT_SECTION_CODE="MTA" ;;
    "TLS CERTIFICATES / LOCAL SERVICES") CURRENT_SECTION_CODE="TLS" ;;
    "DEEP TLS LEGACY PROTOCOL CHECK") CURRENT_SECTION_CODE="TLSLEGACY" ;;
    "DNS / MAIL AUTHENTICATION RECORDS") CURRENT_SECTION_CODE="DNS" ;;
    "LOCAL USERS / PRIVILEGES") CURRENT_SECTION_CODE="USERS" ;;
    "SSH AUTHORIZED_KEYS") CURRENT_SECTION_CODE="KEYS" ;;
    "DISK / FILESYSTEM CAPACITY") CURRENT_SECTION_CODE="DISK" ;;
    "MAIL QUEUE") CURRENT_SECTION_CODE="QUEUE" ;;
    "SUID / SGID") CURRENT_SECTION_CODE="SUID" ;;
    "WORLD-WRITABLE SENSITIVE PATHS") CURRENT_SECTION_CODE="PERMS" ;;
    "FAILED SERVICES / SECURITY FRAMEWORK") CURRENT_SECTION_CODE="MAC" ;;
    "CRON / SYSTEMD TIMERS") CURRENT_SECTION_CODE="SCHED" ;;
    "BACKUP DETECTION") CURRENT_SECTION_CODE="BACKUP" ;;
    "LAST LOGINS") CURRENT_SECTION_CODE="LOGIN" ;;
    "DEEP PACKAGE INTEGRITY") CURRENT_SECTION_CODE="PKG" ;;
    "RECENTLY MODIFIED EXECUTABLE / CONFIG PATHS") CURRENT_SECTION_CODE="RECENT" ;;
    "SUMMARY") CURRENT_SECTION_CODE="SUMMARY" ;;
    *) CURRENT_SECTION_CODE="GEN" ;;
  esac
  printf '\n%s[%02d] %-68s%s\n' "$BOLD$CYAN" "$SECTION_NO" "$1" "$RESET"
  local line; printf -v line '%*s' "$COLUMNS" ''; printf '%s%s%s\n' "$DIM" "${line// /─}" "$RESET"
}
record_finding() {
  local severity="$1" message="$2" id
  FINDING_SEQ=$((FINDING_SEQ+1))
  printf -v id '%s-%03d' "${CURRENT_SECTION_CODE:-GEN}" "$FINDING_SEQ"
  message="${message//$'\t'/ }"; message="${message//$'\n'/ }"
  printf '%s\t%s\t%s\n' "$id" "$severity" "$message" >>"$FINDINGS_FILE"
}
pass()     { printf '%s[  OK  ]%s %s\n' "$GREEN" "$RESET" "$*"; record_finding pass "$*"; ((PASSES+=1)); }
info()     { printf '%s[ INFO ]%s %s\n' "$BLUE" "$RESET" "$*"; record_finding info "$*"; ((INFOS+=1)); }
warn()     { printf '%s[ WARN ]%s %s\n' "$YELLOW" "$RESET" "$*"; record_finding warning "$*"; ((WARNINGS+=1)); }
critical() { printf '%s[ FAIL ]%s %s\n' "$RED" "$RESET" "$*"; record_finding critical "$*"; ((CRITICALS+=1)); }
have()     { command -v "$1" >/dev/null 2>&1; }
kv()       { printf '  %s%-24s%s %s\n' "$DIM" "$1" "$RESET" "$2"; }

run_postconf() {
  if [[ "$MAIL_PLATFORM" == "mailcow" && -n "${MAILCOW_POSTFIX_CONTAINER:-}" ]] && have docker; then
    timeout 20 docker exec "$MAILCOW_POSTFIX_CONTAINER" postconf "$@"
  else
    postconf "$@"
  fi
}

run_doveconf() {
  if [[ "$MAIL_PLATFORM" == "mailcow" && -n "${MAILCOW_DOVECOT_CONTAINER:-}" ]] && have docker; then
    timeout 20 docker exec "$MAILCOW_DOVECOT_CONTAINER" doveconf "$@"
  else
    doveconf "$@"
  fi
}

if [[ -z "$MAIL_HOST" ]]; then
  MAIL_HOST="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo localhost)"
fi

is_systemd_unit_known() {
  local unit="$1" load
  load="$(systemctl show -p LoadState --value "$unit" 2>/dev/null || true)"
  [[ -n "$load" && "$load" != "not-found" ]]
}

unit_state_line() {
  local unit="$1" active enabled
  active="$(systemctl is-active "$unit" 2>/dev/null || true)"
  enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  printf '%-28s active=%-10s enabled=%s\n' "$unit" "${active:-unknown}" "${enabled:-unknown}"
}

collect_journal() {
  local outfile="$1"; shift
  local args=() unit
  if have journalctl; then
    for unit in "$@"; do args+=( -u "$unit" ); done
    journalctl --since "$AUDIT_FROM" --until "$AUDIT_TO" --no-pager -o cat "${args[@]}" >"$outfile" 2>/dev/null || true
  fi
}

collect_fallback_logs() {
  local outfile="$1"; shift
  : >"$outfile"
  local pattern f
  local -a log_files=()
  mapfile -t log_files < <(
    for pattern in "$@"; do
      compgen -G "$pattern" || true
    done | sort -u | while IFS= read -r f; do
      [[ -f "$f" ]] && printf '%s\t%s\n' "$(stat -c '%Y' "$f" 2>/dev/null || echo 0)" "$f"
    done | sort -n | cut -f2-
  )
  for f in "${log_files[@]}"; do
    if [[ "$f" == *.gz ]]; then
      if have zcat; then
        zcat -- "$f" >>"$outfile" 2>/dev/null || true
      fi
    else
      cat -- "$f" >>"$outfile" 2>/dev/null || true
    fi
  done
}

detect_mail_platform() {
  local container=""
  if [[ "$PLATFORM_OVERRIDE" != "auto" ]]; then
    MAIL_PLATFORM="$PLATFORM_OVERRIDE"
  elif have docker; then
    container="$(timeout 8 docker ps -aq --filter label=com.docker.compose.service=postfix-mailcow 2>/dev/null | head -1)"
    if [[ -n "$container" ]]; then
      MAIL_PLATFORM="mailcow"
      MAILCOW_POSTFIX_CONTAINER="$container"
    fi
  fi

  if [[ "$PLATFORM_OVERRIDE" == "auto" && "$MAIL_PLATFORM" == "generic" ]]; then
    if [[ -r /etc/iredmail-release ]]; then
      MAIL_PLATFORM="iredmail"
    elif [[ -r /etc/mailinabox.conf || -d /usr/local/lib/mailinabox || -d /home/user-data/mail/mailboxes ]]; then
      MAIL_PLATFORM="mailinabox"
    fi
  fi

  case "$MAIL_PLATFORM" in
    mailcow)
      if [[ -z "${MAILCOW_POSTFIX_CONTAINER:-}" ]] && have docker; then
        MAILCOW_POSTFIX_CONTAINER="$(timeout 8 docker ps -aq --filter label=com.docker.compose.service=postfix-mailcow 2>/dev/null | head -1)"
      fi
      if have docker; then
        MAILCOW_DOVECOT_CONTAINER="$(timeout 8 docker ps -aq --filter label=com.docker.compose.service=dovecot-mailcow 2>/dev/null | head -1)"
      fi
      if [[ -n "${MAILCOW_POSTFIX_CONTAINER:-}" ]]; then
        PLATFORM_VERSION="$(timeout 8 docker inspect --format '{{.Config.Image}}' "$MAILCOW_POSTFIX_CONTAINER" 2>/dev/null || true)"
      fi
      ;;
    iredmail)
      PLATFORM_VERSION="$(head -1 /etc/iredmail-release 2>/dev/null | tr -cd '[:alnum:]._-')"
      ;;
    mailinabox)
      PLATFORM_VERSION="$(mailinabox --version 2>/dev/null | head -1 || true)"
      ;;
  esac
}

collect_mail_logs() {
  local outfile="$1" since until
  : >"$outfile"
  if [[ "$MAIL_PLATFORM" == "mailcow" && -n "${MAILCOW_POSTFIX_CONTAINER:-}" ]] && have docker; then
    since="$(date -d "$AUDIT_FROM" --iso-8601=seconds)"
    until="$(date -d "$AUDIT_TO" --iso-8601=seconds)"
    timeout 120 docker logs --timestamps --since "$since" --until "$until" \
      "$MAILCOW_POSTFIX_CONTAINER" >"$outfile" 2>/dev/null || true
    if [[ -n "${MAILCOW_DOVECOT_CONTAINER:-}" ]]; then
      timeout 120 docker logs --timestamps --since "$since" --until "$until" \
        "$MAILCOW_DOVECOT_CONTAINER" >>"$outfile" 2>/dev/null || true
    fi
  else
    collect_fallback_logs "$outfile" '/var/log/mail.log*' '/var/log/maillog*' \
      '/var/log/exim4/mainlog*' '/var/log/exim/mainlog*'
    if [[ "$MAIL_PLATFORM" == "iredmail" ]]; then
      collect_fallback_logs "$TMPROOT/iredmail-dovecot.log" '/var/log/dovecot/*.log*'
      cat "$TMPROOT/iredmail-dovecot.log" >>"$outfile" 2>/dev/null || true
    fi
    if [[ ! -s "$outfile" ]] && have journalctl; then
      journalctl --since "$AUDIT_FROM" --until "$AUDIT_TO" --no-pager -o short-iso \
        -u postfix.service -u exim4.service -u exim.service -u dovecot.service \
        -u courier-imap.service -u courier-pop.service >"$outfile" 2>/dev/null || true
    fi
  fi
}

filter_log_period() {
  local source="$1" target="$2"
  python3 - "$SCRIPT_DIR/lib" "$source" "$target" "$AUDIT_FROM" "$AUDIT_TO" <<'PYFILTER'
import datetime as dt
import sys

sys.path.insert(0, sys.argv[1])
from mail_stats import parse_bound, parse_timestamp  # noqa: E402

source, target = sys.argv[2], sys.argv[3]
start, end = parse_bound(sys.argv[4]), parse_bound(sys.argv[5])
now = dt.datetime.now().astimezone().replace(tzinfo=None)
with open(source, encoding="utf-8", errors="replace") as incoming, open(target, "w", encoding="utf-8") as outgoing:
    for line in incoming:
        timestamp = parse_timestamp(line, now)
        if timestamp is not None and start <= timestamp <= end:
            outgoing.write(line)
PYFILTER
}

extract_source_ips() {
  # Один Python-процесс обрабатывает весь поток. Не запускаем Python для каждого IP.
  if have python3; then
    python3 -c '
import collections, ipaddress, re, sys
counts = collections.Counter()
ipv4 = re.compile(r"(?<![0-9A-Fa-f:])(?:\\d{1,3}\\.){3}\\d{1,3}(?![0-9A-Fa-f:])")
ipv6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
for line in sys.stdin:
    seen = set()
    for raw in ipv4.findall(line) + ipv6.findall(line):
        try:
            ip = str(ipaddress.ip_address(raw.strip("[](),;<>")))
        except ValueError:
            continue
        if ip not in seen:
            counts[ip] += 1
            seen.add(ip)
for ip, count in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
    print(f"{count:7d} {ip}")
' 2>/dev/null
  else
    grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn
  fi
}

print_ip_table() {
  local file="$1" title="$2" count ip rank=0 color
  printf '%s%s%s\n' "$BOLD" "$title" "$RESET"
  printf '  %s%-4s %-9s %s%s\n' "$DIM" "#" "EVENTS" "SOURCE IP" "$RESET"
  while read -r count ip; do
    [[ "$count" =~ ^[0-9]+$ && -n "$ip" ]] || continue
    rank=$((rank+1))
    if (( count >= 200 )); then color="$RED"; elif (( count >= 50 )); then color="$YELLOW"; else color="$WHITE"; fi
    printf '  %s%-4d %-9s %-39s%s\n' "$color" "$rank" "$count" "$ip" "$RESET"
  done < <(head -10 "$file" 2>/dev/null)
  (( rank == 0 )) && printf '  %sнет данных%s\n' "$DIM" "$RESET"
}

valid_ipv4_fallback() {
  local ip="$1" octet
  local -a octets=()
  IFS='.' read -r -a octets <<<"$ip"
  ((${#octets[@]} == 4)) || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]+$ && ${#octet} -le 3 ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}

valid_ip() {
  local ip="$1"
  if have python3; then
    python3 - "$ip" <<'PYIP' >/dev/null 2>&1
import ipaddress, sys
ipaddress.ip_address(sys.argv[1])
PYIP
  else
    [[ "$ip" != *:* ]] && valid_ipv4_fallback "$ip"
  fi
}

unsafe_to_ban() {
  local ip="$1" current="${SSH_CONNECTION:-}" own first second third
  current="${current%% *}"
  [[ -n "$current" && "$ip" == "$current" ]] && return 0
  for own in $(hostname -I 2>/dev/null || true); do [[ "$ip" == "$own" ]] && return 0; done
  if have python3; then
    python3 - "$ip" <<'PYIP' >/dev/null 2>&1
import ipaddress, sys
x=ipaddress.ip_address(sys.argv[1])
raise SystemExit(0 if not x.is_global else 1)
PYIP
    return $?
  fi
  # Без надёжной IPv6-библиотеки блокировка IPv6 запрещена (fail closed).
  [[ "$ip" != *:* ]] || return 0
  valid_ipv4_fallback "$ip" || return 0
  IFS='.' read -r first second third _ <<<"$ip"
  first=$((10#$first)); second=$((10#$second)); third=$((10#$third))
  ((
    first == 0 || first == 10 || first == 127 || first >= 224 ||
    (first == 100 && second >= 64 && second <= 127) ||
    (first == 169 && second == 254) ||
    (first == 172 && second >= 16 && second <= 31) ||
    (first == 192 && second == 0 && (third == 0 || third == 2)) ||
    (first == 192 && second == 168) ||
    (first == 198 && (second == 18 || second == 19)) ||
    (first == 198 && second == 51 && third == 100) ||
    (first == 203 && second == 0 && third == 113)
  ))
}

load_f2b_jails() {
  fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' \
    | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d'
}

choose_jail() {
  local prompt="${1:-Выбери jail}" i=0 answer
  mapfile -t MENU_JAILS < <(load_f2b_jails)
  ((${#MENU_JAILS[@]})) || return 1
  printf '\n%s%s:%s\n' "$BOLD" "$prompt" "$RESET" >&2
  for i in "${!MENU_JAILS[@]}"; do printf '  %s%2d)%s %s\n' "$CYAN" "$((i+1))" "$RESET" "${MENU_JAILS[$i]}" >&2; done
  read -r -p "Номер jail [0=отмена]: " answer
  [[ "$answer" =~ ^[0-9]+$ ]] || return 1
  (( answer >= 1 && answer <= ${#MENU_JAILS[@]} )) || return 1
  CHOSEN_JAIL="${MENU_JAILS[$((answer-1))]}"
}

pick_candidate_ip() {
  local answer i count ip
  mapfile -t CANDIDATE_LINES < <(cat "$TMPROOT/ssh-top-ips.txt" "$TMPROOT/mail-top-ips.txt" 2>/dev/null \
    | awk '{sum[$2]+=$1} END {for (ip in sum) print sum[ip],ip}' | sort -rn | head -15)
  printf '\n%sКандидаты из текущего отчёта:%s\n' "$BOLD" "$RESET"
  for i in "${!CANDIDATE_LINES[@]}"; do
    read -r count ip <<<"${CANDIDATE_LINES[$i]}"
    printf '  %s%2d)%s %-7s %s\n' "$CYAN" "$((i+1))" "$RESET" "$count" "$ip"
  done
  printf '  %s m)%s ввести IP вручную\n' "$CYAN" "$RESET"
  read -r -p "Выбор [0=отмена]: " answer
  [[ "$answer" == 0 ]] && return 1
  if [[ "$answer" == m || "$answer" == M ]]; then
    read -r -p "IP: " CHOSEN_IP
  elif [[ "$answer" =~ ^[0-9]+$ ]] && (( answer >= 1 && answer <= ${#CANDIDATE_LINES[@]} )); then
    CHOSEN_IP="$(awk '{print $2}' <<<"${CANDIDATE_LINES[$((answer-1))]}")"
  else
    return 1
  fi
  valid_ip "$CHOSEN_IP"
}

show_banned_ips() {
  local jail ips any=0
  printf '\n%sТекущие блокировки Fail2ban%s\n' "$BOLD" "$RESET"
  while IFS= read -r jail; do
    ips="$(fail2ban-client get "$jail" banip 2>/dev/null || true)"
    [[ -n "$ips" ]] || continue
    any=1; printf '  %s%-24s%s %s\n' "$MAGENTA" "$jail" "$RESET" "$ips"
  done < <(load_f2b_jails)
  (( any == 0 )) && info "Сейчас заблокированных IP не найдено"
}

interactive_ban_menu() {
  [[ -t 0 && -t 1 ]] || { info "Интерактивное меню пропущено: нет TTY"; return; }
  (( EUID == 0 )) || { warn "Для управления Fail2ban нужен root"; return; }
  if ! have fail2ban-client || ! fail2ban-client ping 2>/dev/null | grep -qi pong; then
    warn "Fail2ban недоступен — меню управления не открыто"
    return
  fi

  local action confirm jail ip
  while true; do
    printf '\n%s' "$CYAN$BOLD"; hr; printf '  FAIL2BAN ACTIONS — изменения только после подтверждения\n'; hr; printf '%s' "$RESET"
    printf '  %s1)%s Заблокировать один IP в выбранном jail\n' "$CYAN" "$RESET"
    printf '  %s2)%s Разблокировать IP во всех jail\n' "$CYAN" "$RESET"
    printf '  %s3)%s Показать текущие блокировки\n' "$CYAN" "$RESET"
    printf '  %s0)%s Выйти без изменений\n' "$CYAN" "$RESET"
    read -r -p "Действие: " action
    case "$action" in
      1)
        pick_candidate_ip || { warn "IP не выбран или невалиден"; continue; }
        ip="$CHOSEN_IP"
        if unsafe_to_ban "$ip"; then critical "Блокировка $ip запрещена защитой от self-lockout/private IP"; continue; fi
        choose_jail "Jail для $ip" || { info "Операция отменена"; continue; }
        jail="$CHOSEN_JAIL"
        printf '%sБудет выполнено:%s fail2ban-client set %s banip %s\n' "$YELLOW" "$RESET" "$jail" "$ip"
        read -r -p "Для подтверждения введи BAN: " confirm
        [[ "$confirm" == BAN ]] || { info "Операция отменена"; continue; }
        if fail2ban-client set "$jail" banip "$ip" >/dev/null; then
          pass "IP $ip заблокирован в jail $jail"
          logger -t mail-sec-audit "manual ban ip=$ip jail=$jail user=${SUDO_USER:-root}" 2>/dev/null || true
        else critical "Fail2ban не смог заблокировать $ip"; fi
        ;;
      2)
        read -r -p "IP для разблокировки: " ip
        valid_ip "$ip" || { warn "Невалидный IP"; continue; }
        printf '%sБудет снята блокировка %s во всех jail.%s\n' "$YELLOW" "$ip" "$RESET"
        read -r -p "Для подтверждения введи UNBAN: " confirm
        [[ "$confirm" == UNBAN ]] || { info "Операция отменена"; continue; }
        if fail2ban-client unban "$ip" >/dev/null 2>&1; then
          pass "IP $ip разблокирован"
        else
          while IFS= read -r jail; do fail2ban-client set "$jail" unbanip "$ip" >/dev/null 2>&1 || true; done < <(load_f2b_jails)
          pass "Команда разблокировки $ip отправлена во все jail"
        fi
        logger -t mail-sec-audit "manual unban ip=$ip user=${SUDO_USER:-root}" 2>/dev/null || true
        ;;
      3) show_banned_ips ;;
      0|'') break ;;
      *) warn "Неизвестный пункт меню" ;;
    esac
  done
}

check_usage_table() {
  local mode="$1" alerts=0
  while read -r filesystem _ _ _ percent mountpoint; do
    [[ "$percent" =~ ^[0-9]+%$ ]] || continue
    local value="${percent%%%}"
    if (( value >= 95 )); then
      critical "$mode заполнение $percent: $mountpoint ($filesystem)"
      alerts=$((alerts+1))
    elif (( value >= 85 )); then
      warn "$mode заполнение $percent: $mountpoint ($filesystem)"
      alerts=$((alerts+1))
    fi
  done
  (( alerts == 0 )) && pass "$mode: пороги 85%/95% не превышены"
}

detect_mail_storage_path() {
  local storage_root
  case "$MAIL_PLATFORM" in
    mailcow)
      if have docker && [[ -n "${MAILCOW_DOVECOT_CONTAINER:-}" ]]; then
        timeout 8 docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/vmail"}}{{.Source}}{{end}}{{end}}' \
          "$MAILCOW_DOVECOT_CONTAINER" 2>/dev/null || true
      fi
      ;;
    iredmail)
      [[ -d /var/vmail ]] && printf '%s\n' /var/vmail
      ;;
    mailinabox)
      storage_root="$(sed -n 's/^STORAGE_ROOT=//p' /etc/mailinabox.conf 2>/dev/null | tail -1)"
      storage_root="${storage_root:-/home/user-data}"
      [[ -d "$storage_root/mail/mailboxes" ]] && printf '%s\n' "$storage_root/mail/mailboxes"
      ;;
    *)
      if have postconf; then
        storage_root="$(postconf -h virtual_mailbox_base 2>/dev/null || true)"
        [[ -d "$storage_root" ]] && printf '%s\n' "$storage_root"
      fi
      ;;
  esac
}

probe_tls() {
  local label="$1" port="$2" starttls="${3:-}"
  local outfile="$TMPROOT/tls-${port}-${starttls:-plain}.txt"
  local cmd=(openssl s_client -connect "127.0.0.1:$port" -servername "$MAIL_HOST" -showcerts)
  [[ -n "$starttls" ]] && cmd+=( -starttls "$starttls" )

  if ! timeout 12 "${cmd[@]}" </dev/null >"$outfile" 2>/dev/null; then
    warn "$label: TLS handshake не выполнен на 127.0.0.1:$port"
    return
  fi

  if ! openssl x509 -in "$outfile" -noout >/dev/null 2>&1; then
    warn "$label: сервер не отдал читаемый сертификат"
    return
  fi

  local subject issuer not_before not_after end_epoch now_epoch days_left
  subject="$(openssl x509 -in "$outfile" -noout -subject 2>/dev/null | sed 's/^subject=//')"
  issuer="$(openssl x509 -in "$outfile" -noout -issuer 2>/dev/null | sed 's/^issuer=//')"
  not_before="$(openssl x509 -in "$outfile" -noout -startdate 2>/dev/null | cut -d= -f2-)"
  not_after="$(openssl x509 -in "$outfile" -noout -enddate 2>/dev/null | cut -d= -f2-)"
  printf '%s\n' "  Subject: $subject" "  Issuer:  $issuer" "  Valid:   $not_before -> $not_after"

  if end_epoch="$(date -d "$not_after" +%s 2>/dev/null)"; then
    now_epoch="$(date +%s)"
    days_left=$(( (end_epoch - now_epoch) / 86400 ))
    if (( days_left < 0 )); then
      critical "$label: сертификат истёк ${days_left#-} дн. назад"
    elif (( days_left < 14 )); then
      critical "$label: сертификат истекает через $days_left дн."
    elif (( days_left < 30 )); then
      warn "$label: сертификат истекает через $days_left дн."
    else
      pass "$label: сертификат действителен ещё $days_left дн."
    fi
  fi

  if openssl x509 -in "$outfile" -noout -checkhost "$MAIL_HOST" >/dev/null 2>&1; then
    pass "$label: имя $MAIL_HOST присутствует в сертификате"
  else
    warn "$label: сертификат не подтверждает имя $MAIL_HOST"
  fi
}


print_mailbox_stats_table() {
  local file="$1" title="$2" address submitted messages deliveries bytes first last rank=0
  printf '%s%s%s\n' "$BOLD" "$title" "$RESET"
  printf '  %s%-4s %-32s %9s %9s %10s %12s%s\n' "$DIM" "#" "MAILBOX / SENDER" "SUBMITTED" "DELIVERED" "RECIPIENTS" "BYTES" "$RESET"
  while IFS=$'\t' read -r address submitted messages deliveries bytes first last; do
    [[ "$messages" =~ ^[0-9]+$ ]] || continue
    rank=$((rank+1))
    printf '  %-4d %-32.32s %9s %9s %10s %12s\n' "$rank" "$address" "$submitted" "$messages" "$deliveries" "$bytes"
    (( VERBOSE == 1 )) && printf '       period: %s -> %s\n' "$first" "$last"
  done <"$file"
  (( rank == 0 )) && printf '  %sнет данных%s\n' "$DIM" "$RESET"
}

print_domain_stats_table() {
  local file="$1" title="$2" domain count rank=0
  printf '%s%s%s\n' "$BOLD" "$title" "$RESET"
  printf '  %s%-4s %-50s %10s%s\n' "$DIM" "#" "DOMAIN" "COUNT" "$RESET"
  while IFS=$'\t' read -r domain count; do
    [[ "$count" =~ ^[0-9]+$ ]] || continue
    rank=$((rank+1))
    printf '  %-4d %-50.50s %10s\n' "$rank" "$domain" "$count"
  done <"$file"
  (( rank == 0 )) && printf '  %sнет данных%s\n' "$DIM" "$RESET"
}

load_mail_stats_summary() {
  while IFS=$'\t' read -r key value; do
    case "$key" in
      outbound_messages) MAIL_OUTBOUND_MESSAGES="$value" ;;
      authenticated_submissions) MAIL_AUTH_SUBMISSIONS="$value" ;;
      authenticated_outbound_messages) MAIL_AUTH_OUTBOUND_MESSAGES="$value" ;;
      outbound_deliveries) MAIL_OUTBOUND_DELIVERIES="$value" ;;
      incoming_messages) MAIL_INCOMING_MESSAGES="$value" ;;
      incoming_deliveries) MAIL_INCOMING_DELIVERIES="$value" ;;
      bounced_deliveries) MAIL_BOUNCED_DELIVERIES="$value" ;;
      deferred_deliveries) MAIL_DEFERRED_DELIVERIES="$value" ;;
      outbound_bytes) MAIL_OUTBOUND_BYTES="$value" ;;
      lines_scanned) MAIL_LINES_SCANNED="$value" ;;
      lines_in_period) MAIL_LINES_IN_PERIOD="$value" ;;
      observed_from) MAIL_OBSERVED_FROM="$value" ;;
      observed_to) MAIL_OBSERVED_TO="$value" ;;
    esac
  done < <(python3 - "$MAIL_STATS_JSON" <<'PYSUMMARY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
totals = data.get("totals", {})
for key in (
    "outbound_messages", "authenticated_submissions", "authenticated_outbound_messages", "outbound_deliveries",
    "incoming_messages", "incoming_deliveries", "bounced_deliveries",
    "deferred_deliveries", "outbound_bytes"
):
    print(f"{key}\t{totals.get(key, 0)}")
source = data.get("source", {})
print(f"lines_scanned\t{source.get('lines_scanned', 0)}")
print(f"lines_in_period\t{source.get('lines_in_period', 0)}")
period = data.get("period", {})
print(f"observed_from\t{period.get('observed_from') or '-'}")
print(f"observed_to\t{period.get('observed_to') or '-'}")
PYSUMMARY
  )
}

detect_mail_platform
banner
section "AUDIT CONTEXT"
kv "Date" "$(date --iso-8601=seconds 2>/dev/null || date)"
kv "Host" "$(hostname 2>/dev/null || true)"
kv "FQDN / TLS name" "$MAIL_HOST"
kv "Mail domain" "${MAIL_DOMAIN:-(not specified)}"
kv "Platform" "$MAIL_PLATFORM ${PLATFORM_VERSION:+($PLATFORM_VERSION)}"
kv "Analysis period" "$AUDIT_FROM -> $AUDIT_TO"
kv "Kernel" "$(uname -srmo 2>/dev/null || uname -a)"
if [[ -r /etc/os-release ]]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  kv "OS" "${PRETTY_NAME:-unknown}"
fi
if (( EUID == 0 )); then
  pass "Запущено от root: доступны все локальные проверки"
else
  warn "Запущено не от root: часть данных будет недоступна"
fi
if [[ "$MAIL_HOST" == *.* ]]; then
  pass "Hostname выглядит как FQDN"
else
  warn "Hostname '$MAIL_HOST' не выглядит как FQDN"
fi

section "PATCHES / REBOOT"
if have apt-get; then
  pending="$(timeout 90 apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | awk '/^Inst /{c++} END{print c+0}')"
  security_pending="$(apt list --upgradable 2>/dev/null | grep -Eic '(security|updates-security)' || true)"
  echo "Pending packages: ${pending:-unknown}"
  echo "Security-related lines: ${security_pending:-0}"
  if [[ "${security_pending:-0}" =~ ^[0-9]+$ ]] && (( security_pending > 0 )); then
    warn "Есть доступные security-обновления: $security_pending"
  elif [[ "${pending:-0}" =~ ^[0-9]+$ ]] && (( pending > 0 )); then
    warn "Есть доступные обновления: $pending"
  else
    pass "По текущему APT-кэшу обновлений не найдено"
  fi
  if [[ -d /var/lib/apt/lists ]]; then
    newest_list="$(find /var/lib/apt/lists -type f -printf '%T@\n' 2>/dev/null | sort -nr | head -1 | cut -d. -f1)"
    if [[ "$newest_list" =~ ^[0-9]+$ ]]; then
      age_days=$(( ($(date +%s) - newest_list) / 86400 ))
      if (( age_days > 7 )); then
        warn "APT metadata старше 7 дней: ${age_days} дн.; число обновлений может быть неточным"
      else
        info "Возраст APT metadata: ${age_days} дн."
      fi
    fi
  fi
  if have apt-config; then
    apt-config dump 2>/dev/null | grep -E 'APT::Periodic::(Enable|Update-Package-Lists|Unattended-Upgrade)' || true
  fi
elif have dnf; then
  dnf_output="$TMPROOT/dnf-check.txt"
  timeout 120 dnf -C -q check-update >"$dnf_output" 2>/dev/null || rc=$?
  rc="${rc:-0}"
  updates="$(awk 'NF>=3 && $1 !~ /^(Last|Obsoleting|Security:|$)/ {c++} END{print c+0}' "$dnf_output")"
  echo "Pending packages: $updates"
  if (( updates > 0 )); then
    warn "Есть доступные DNF-обновления: $updates"
  else
    pass "DNF не сообщил доступных обновлений"
  fi
elif have yum; then
  yum_output="$TMPROOT/yum-check.txt"
  timeout 120 yum -C -q check-update >"$yum_output" 2>/dev/null || true
  updates="$(awk 'NF>=3 && $1 !~ /^(Loaded|Security:|$)/ {c++} END{print c+0}' "$yum_output")"
  echo "Pending packages: $updates"
  if (( updates > 0 )); then
    warn "Есть доступные YUM-обновления: $updates"
  else
    pass "YUM не сообщил доступных обновлений"
  fi
else
  info "Поддерживаемый пакетный менеджер не найден"
fi

if [[ -f /var/run/reboot-required ]]; then
  warn "Требуется перезагрузка: $(tr '\n' ' ' </var/run/reboot-required.pkgs 2>/dev/null || true)"
else
  pass "Маркер reboot-required отсутствует"
fi

section "MAIL PLATFORM / STACK DETECTION"
if [[ "$MAIL_PLATFORM" == "mailcow" ]]; then
  MTA="postfix"
  IMAP_SERVER="dovecot"
elif systemctl is-active --quiet postfix.service 2>/dev/null; then
  MTA="postfix"
elif systemctl is-active --quiet exim4.service 2>/dev/null || systemctl is-active --quiet exim.service 2>/dev/null; then
  MTA="exim"
elif systemctl is-active --quiet opensmtpd.service 2>/dev/null; then
  MTA="opensmtpd"
elif systemctl is-active --quiet sendmail.service 2>/dev/null; then
  MTA="sendmail"
elif have postconf || is_systemd_unit_known postfix.service; then
  MTA="postfix"
elif have exim || have exim4 || is_systemd_unit_known exim4.service || is_systemd_unit_known exim.service; then
  MTA="exim"
elif have smtpctl || is_systemd_unit_known opensmtpd.service; then
  MTA="opensmtpd"
elif have sendmail || is_systemd_unit_known sendmail.service; then
  MTA="sendmail"
fi

if systemctl is-active --quiet dovecot.service 2>/dev/null; then
  IMAP_SERVER="dovecot"
elif systemctl is-active --quiet courier-imap.service 2>/dev/null; then
  IMAP_SERVER="courier"
elif have doveconf || is_systemd_unit_known dovecot.service; then
  IMAP_SERVER="dovecot"
elif have courierauthconfig || is_systemd_unit_known courier-imap.service; then
  IMAP_SERVER="courier"
fi

echo "Detected platform:   $MAIL_PLATFORM"
echo "Platform version:    ${PLATFORM_VERSION:-unknown}"
echo "Detected MTA:         $MTA"
echo "Detected IMAP/POP3:   $IMAP_SERVER"

if have systemctl; then
  for unit in postfix.service exim4.service exim.service sendmail.service opensmtpd.service \
              dovecot.service courier-imap.service courier-pop.service rspamd.service \
              spamassassin.service amavis.service clamav-daemon.service clamd@scan.service \
              opendkim.service opendmarc.service nginx.service apache2.service httpd.service \
              fail2ban.service iredapd.service sogo.service mariadb.service mysql.service \
              redis-server.service; do
    is_systemd_unit_known "$unit" && unit_state_line "$unit"
  done
fi

if [[ "$MAIL_PLATFORM" == "mailcow" ]]; then
  mailcow_postfix_running="$(timeout 8 docker ps -q --filter label=com.docker.compose.service=postfix-mailcow 2>/dev/null | head -1)"
  mailcow_dovecot_running="$(timeout 8 docker ps -q --filter label=com.docker.compose.service=dovecot-mailcow 2>/dev/null | head -1)"
  if [[ -n "$mailcow_postfix_running" ]]; then
    pass "Mailcow Postfix container активен"
  else
    critical "Mailcow Postfix container не запущен"
  fi
  if [[ -n "$mailcow_dovecot_running" ]]; then
    pass "Mailcow Dovecot container активен"
  else
    critical "Mailcow Dovecot container не запущен"
  fi
  mailcow_project="$(timeout 8 docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' \
    "$MAILCOW_POSTFIX_CONTAINER" 2>/dev/null || true)"
  if [[ -n "$mailcow_project" ]]; then
    echo "-- Mailcow containers --"
    timeout 12 docker ps -a --filter "label=com.docker.compose.project=$mailcow_project" \
      --format 'table {{.Names}}\t{{.Status}}' 2>/dev/null || true
    mailcow_unhealthy="$(timeout 12 docker ps -a --filter "label=com.docker.compose.project=$mailcow_project" \
      --format '{{.Names}}\t{{.Status}}' 2>/dev/null | grep -Eic 'unhealthy|restarting|exited' || true)"
    if (( ${mailcow_unhealthy:-0} > 0 )); then
      critical "Mailcow: контейнеры unhealthy/restarting/exited: $mailcow_unhealthy"
    else
      pass "Mailcow: проблемных состояний контейнеров не найдено"
    fi
  fi
elif [[ "$MAIL_PLATFORM" == "mailinabox" ]]; then
  pass "Mail-in-a-Box обнаружен; используются штатные Postfix/Dovecot логи"
elif [[ "$MAIL_PLATFORM" == "iredmail" ]]; then
  pass "iRedMail обнаружен по /etc/iredmail-release"
fi

case "$MTA" in
  postfix)
    if [[ "$MAIL_PLATFORM" == "mailcow" ]]; then
      : # Состояние контейнера проверено выше.
    elif systemctl is-active --quiet postfix 2>/dev/null; then
      pass "Postfix активен"
    else
      critical "Postfix обнаружен, но не active"
    fi
    ;;
  exim)
    if systemctl is-active --quiet exim4 2>/dev/null || systemctl is-active --quiet exim 2>/dev/null; then
      pass "Exim активен"
    else
      critical "Exim обнаружен, но не active"
    fi
    ;;
  opensmtpd)
    if systemctl is-active --quiet opensmtpd 2>/dev/null; then
      pass "OpenSMTPD активен"
    else
      critical "OpenSMTPD обнаружен, но не active"
    fi
    ;;
  sendmail)
    if systemctl is-active --quiet sendmail 2>/dev/null; then
      pass "Sendmail активен"
    else
      warn "Sendmail обнаружен, но systemd не подтверждает active"
    fi
    ;;
  none)
    critical "MTA не обнаружен"
    ;;
esac

if [[ "$IMAP_SERVER" == "dovecot" ]]; then
  if [[ "$MAIL_PLATFORM" == "mailcow" ]]; then
    : # Состояние контейнера проверено выше.
  elif systemctl is-active --quiet dovecot 2>/dev/null; then
    pass "Dovecot активен"
  else
    critical "Dovecot обнаружен, но не active"
  fi
elif [[ "$IMAP_SERVER" == "courier" ]]; then
  if systemctl is-active --quiet courier-imap 2>/dev/null; then
    pass "Courier IMAP активен"
  else
    warn "Courier обнаружен, но не active"
  fi
else
  info "IMAP/POP3-сервис не обнаружен; для relay-only SMTP это нормально"
fi

section "SSHD EFFECTIVE CONFIG"
if have sshd; then
  sshd_config="$TMPROOT/sshd-T.txt"
  sshd -T >"$sshd_config" 2>/dev/null || true
  grep -Ei '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|challengeresponseauthentication|x11forwarding|maxauthtries|maxsessions|logingracetime|allowusers|allowgroups|denyusers|denygroups|authenticationmethods) ' "$sshd_config" || true

  ssh_port="$(awk '$1=="port"{print $2; exit}' "$sshd_config")"
  permit_root="$(awk '$1=="permitrootlogin"{print $2; exit}' "$sshd_config")"
  pass_auth="$(awk '$1=="passwordauthentication"{print $2; exit}' "$sshd_config")"
  pubkey_auth="$(awk '$1=="pubkeyauthentication"{print $2; exit}' "$sshd_config")"
  kbd_auth="$(awk '$1=="kbdinteractiveauthentication"{print $2; exit}' "$sshd_config")"
  x11="$(awk '$1=="x11forwarding"{print $2; exit}' "$sshd_config")"
  maxtries="$(awk '$1=="maxauthtries"{print $2; exit}' "$sshd_config")"

  if [[ "$permit_root" == "yes" && "$pass_auth" == "yes" ]]; then
    critical "SSH: root login и password authentication одновременно разрешены"
  elif [[ "$permit_root" == "yes" ]]; then
    warn "SSH: PermitRootLogin=yes"
  elif [[ "$permit_root" == "prohibit-password" || "$permit_root" == "without-password" ]]; then
    warn "SSH: root разрешён по ключу; безопаснее отдельный sudo-user"
  else
    pass "SSH: прямой root login запрещён"
  fi
  if [[ "$pass_auth" == "yes" ]]; then
    warn "SSH: PasswordAuthentication=yes"
  else
    pass "SSH: password authentication отключена"
  fi
  if [[ "$pubkey_auth" == "yes" ]]; then
    pass "SSH: public key authentication включена"
  else
    warn "SSH: PubkeyAuthentication отключена"
  fi
  if [[ "$kbd_auth" == "yes" ]]; then
    info "SSH: keyboard-interactive включён; проверь PAM/MFA"
  fi
  if [[ "$x11" == "yes" ]]; then
    warn "SSH: X11Forwarding=yes на почтовом сервере"
  else
    pass "SSH: X11 forwarding отключён"
  fi
  if [[ "$maxtries" =~ ^[0-9]+$ ]] && (( maxtries > 6 )); then
    warn "SSH: MaxAuthTries=$maxtries"
  fi
else
  warn "sshd не найден или недоступен"
  ssh_port="22"
fi

section "LISTENING PORTS / PUBLIC BINDS"
if have ss; then
  (( VERBOSE == 1 )) && { ss -lntup 2>/dev/null || ss -lntu 2>/dev/null || true; }
  printf '  %s%-7s %-42s %s%s\n' "$DIM" "PROTO" "NON-LOOPBACK ENDPOINT" "ASSESSMENT" "$RESET"
  known_ports="22 25 53 80 110 143 443 465 587 993 995 4190 ${ssh_port:-} $MAIL_AUDIT_ALLOWED_PORTS"
  unexpected=0
  while read -r proto endpoint; do
    [[ -n "$endpoint" ]] || continue
    case "$endpoint" in
      127.0.0.1:*|127.*:*|\[::1\]:*|::1:*|localhost:*) continue ;;
    esac
    port="${endpoint##*:}"
    port="${port%]}"
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    if [[ " $known_ports " != *" $port "* ]]; then
      printf '  %s%-7s %-42s REVIEW%s\n' "$YELLOW" "$proto" "$endpoint" "$RESET"
      warn "Неизвестный non-loopback listener: $proto $endpoint"
      unexpected=$((unexpected+1))
    else
      printf '  %s%-7s %-42s expected%s\n' "$GREEN" "$proto" "$endpoint" "$RESET"
    fi
  done < <(ss -H -lntu 2>/dev/null | awk '{print $1, $5}')
  (( unexpected == 0 )) && pass "Неожиданных non-loopback портов по базовому allowlist не найдено"
else
  warn "Команда ss не найдена"
fi

section "FIREWALL"
firewall_active=0
if have ufw; then
  ufw status verbose 2>/dev/null || true
  if ufw status 2>/dev/null | grep -q '^Status: active'; then
    pass "UFW активен"; firewall_active=1
  else
    info "UFW установлен, но не активен"
  fi
fi
if have firewall-cmd; then
  if firewall-cmd --state 2>/dev/null | grep -q running; then
    pass "firewalld активен"; firewall_active=1
    firewall-cmd --get-active-zones 2>/dev/null || true
    firewall-cmd --list-all 2>/dev/null || true
  else
    info "firewalld установлен, но не активен"
  fi
fi
if have nft; then
  nft_rules="$TMPROOT/nft.txt"
  nft list ruleset >"$nft_rules" 2>/dev/null || true
  if grep -qE 'hook (input|forward|output)' "$nft_rules"; then
    pass "nftables ruleset содержит hook-цепочки"; firewall_active=1
    (( VERBOSE == 1 )) && sed -n '1,160p' "$nft_rules"
  fi
fi
if (( firewall_active == 0 )) && have iptables; then
  if (( VERBOSE == 1 )); then
    iptables -L -n --line-numbers 2>/dev/null | sed -n '1,120p' || true
  fi
  if iptables -S 2>/dev/null | grep -qE '^-A '; then
    pass "Найдены iptables rules"; firewall_active=1
  fi
fi
(( firewall_active == 0 )) && critical "Активный host firewall не обнаружен"

section "BRUTE-FORCE PROTECTION"
bruteforce_protection=0
if [[ "$MAIL_PLATFORM" == "mailcow" ]] && have docker; then
  mailcow_netfilter="$(timeout 8 docker ps -q --filter label=com.docker.compose.service=netfilter-mailcow 2>/dev/null | head -1)"
  if [[ -n "$mailcow_netfilter" ]]; then
    pass "Mailcow netfilter container активен"
    bruteforce_protection=1
  else
    critical "Mailcow netfilter container не запущен"
  fi
fi
if have fail2ban-client; then
  if fail2ban-client ping 2>/dev/null | grep -qi pong; then
    pass "Fail2ban отвечает"; bruteforce_protection=1
  else
    critical "Fail2ban установлен, но не отвечает"
  fi
  f2b_status="$(fail2ban-client status 2>/dev/null || true)"
  echo "$f2b_status"
  jails="$(printf '%s\n' "$f2b_status" | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d')"
  if [[ -z "$jails" ]]; then
    warn "Fail2ban не сообщил активных jail"
  else
    printf '  %s%-24s %-12s %-12s%s\n' "$DIM" "JAIL" "BANNED NOW" "TOTAL" "$RESET"
    while IFS= read -r jail; do
      [[ -n "$jail" ]] || continue
      js="$(fail2ban-client status "$jail" 2>/dev/null || true)"
      banned="$(printf '%s\n' "$js" | awk -F: '/Currently banned/{gsub(/ /,"",$2);print $2}')"
      total="$(printf '%s\n' "$js" | awk -F: '/Total banned/{gsub(/ /,"",$2);print $2}')"
      if [[ "${banned:-0}" =~ ^[0-9]+$ ]] && (( banned > 0 )); then
        printf '  %s%-24s %-12s %-12s%s\n' "$RED" "$jail" "${banned:-?}" "${total:-?}" "$RESET"
      else
        printf '  %s%-24s %-12s %-12s%s\n' "$GREEN" "$jail" "${banned:-?}" "${total:-?}" "$RESET"
      fi
    done <<<"$jails"
  fi
else
  info "Fail2ban не установлен или fail2ban-client отсутствует"
fi
if systemctl is-active --quiet crowdsec.service 2>/dev/null; then
  pass "CrowdSec активен"; bruteforce_protection=1
  if have cscli; then
    cscli metrics 2>/dev/null | sed -n '1,120p' || true
  fi
fi
if systemctl is-active --quiet sshguard.service 2>/dev/null; then
  pass "sshguard активен"; bruteforce_protection=1
fi
(( bruteforce_protection == 0 )) && warn "Fail2ban/CrowdSec/sshguard не обнаружены; проверь альтернативную защиту"

section "AUTHENTICATION EVENTS"
ssh_log="$TMPROOT/ssh.log"
collect_journal "$ssh_log" ssh.service sshd.service
if [[ ! -s "$ssh_log" ]]; then
  collect_fallback_logs "$ssh_log" '/var/log/auth.log*' '/var/log/secure*'
  info "SSH-статистика получена из файлов логов; точный период может отличаться от $DAYS дней"
fi

info "Анализирую SSH-события одним проходом..."
if have python3; then
  python3 - "$ssh_log" "$TMPROOT/ssh-top-ips.txt" "$TMPROOT/ssh-accepted-ips.txt" >"$TMPROOT/ssh-summary.txt" <<'PYSSH'
import collections
import ipaddress
import re
import sys

log_file, failed_out, accepted_out = sys.argv[1:4]
failed = accepted = sessions = 0
failed_ips = collections.Counter()
accepted_ips = collections.Counter()

fail_re = re.compile(r'Failed password|Invalid user|authentication failure|PAM.*failure', re.I)
accept_re = re.compile(r'Accepted (?:publickey|password)', re.I)
session_re = re.compile(r'session opened for user', re.I)
from_ip_re = re.compile(r'\\bfrom\\s+([^\\s]+)', re.I)
rhost_re = re.compile(r'\\brhost=([^\\s]+)', re.I)


def normalize(raw):
    raw = raw.strip('[](),;<>')
    if raw.startswith('::ffff:'):
        raw = raw[7:]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None

with open(log_file, 'r', encoding='utf-8', errors='replace') as fh:
    for line in fh:
        is_fail = bool(fail_re.search(line))
        is_accept = bool(accept_re.search(line))
        if is_fail:
            failed += 1
        if is_accept:
            accepted += 1
        if session_re.search(line):
            sessions += 1
        if not (is_fail or is_accept):
            continue
        match = from_ip_re.search(line) or rhost_re.search(line)
        if not match:
            continue
        ip = normalize(match.group(1))
        if not ip:
            continue
        (failed_ips if is_fail else accepted_ips)[ip] += 1

with open(failed_out, 'w', encoding='utf-8') as fh:
    for ip, count in sorted(failed_ips.items(), key=lambda x: (-x[1], x[0])):
        fh.write(f'{count:7d} {ip}\\n')
with open(accepted_out, 'w', encoding='utf-8') as fh:
    for ip, count in sorted(accepted_ips.items(), key=lambda x: (-x[1], x[0])):
        fh.write(f'{count:7d} {ip}\\n')

print(f'failed={failed}')
print(f'accepted={accepted}')
print(f'sessions={sessions}')
PYSSH
  ssh_failed="$(awk -F= '$1=="failed"{print $2}' "$TMPROOT/ssh-summary.txt")"
  ssh_accepted="$(awk -F= '$1=="accepted"{print $2}' "$TMPROOT/ssh-summary.txt")"
  ssh_sessions="$(awk -F= '$1=="sessions"{print $2}' "$TMPROOT/ssh-summary.txt")"
else
  ssh_failed="$(grep -Eic 'Failed password|Invalid user|authentication failure|PAM.*failure' "$ssh_log" 2>/dev/null || true)"
  ssh_accepted="$(grep -Eic 'Accepted (publickey|password)' "$ssh_log" 2>/dev/null || true)"
  ssh_sessions="$(grep -Eic 'session opened for user' "$ssh_log" 2>/dev/null || true)"
  grep -Ei 'Failed password|Invalid user|authentication failure|PAM.*failure' "$ssh_log" 2>/dev/null | extract_source_ips >"$TMPROOT/ssh-top-ips.txt" || true
  grep -Ei 'Accepted (publickey|password)' "$ssh_log" 2>/dev/null | extract_source_ips >"$TMPROOT/ssh-accepted-ips.txt" || true
fi

kv "SSH failed / invalid" "${ssh_failed:-0}"
kv "SSH accepted logins" "${ssh_accepted:-0}"
kv "SSH sessions opened" "${ssh_sessions:-0}"
print_ip_table "$TMPROOT/ssh-top-ips.txt" "Top source IPs — SSH failures"
print_ip_table "$TMPROOT/ssh-accepted-ips.txt" "Top source IPs — successful SSH logins"
ssh_rate=$(( ${ssh_failed:-0} / (DAYS > 0 ? DAYS : 1) ))
if (( ssh_rate > 100 )); then
  warn "Высокая интенсивность SSH failures: около $ssh_rate событий/сутки"
fi

mail_log="$TMPROOT/mail.log"
collect_mail_logs "$mail_log"
mail_auth_log="$mail_log"
if [[ -s "$mail_log" && -r "$SCRIPT_DIR/lib/mail_stats.py" ]] && have python3; then
  if filter_log_period "$mail_log" "$TMPROOT/mail-period.log"; then
    mail_auth_log="$TMPROOT/mail-period.log"
  else
    warn "Не удалось отфильтровать auth-события по выбранному периоду"
  fi
fi
if [[ "$MAIL_PLATFORM" == "mailcow" ]]; then
  info "Почтовые события получены из Docker logs контейнера postfix-mailcow"
elif [[ -s "$mail_log" ]]; then
  info "Почтовые события получены из системных и ротационных mail logs"
fi
info "Анализирую ошибки почтовой авторизации..."
mail_auth_failed="$(grep -Eic 'SASL.*authentication failed|auth failed|authentication failure|Aborted login|LOGIN FAILED|535[ -].*auth|authenticator failed' "$mail_auth_log" 2>/dev/null || true)"
kv "Mail auth failures" "${mail_auth_failed:-0}"
grep -Ei 'SASL.*authentication failed|auth failed|authentication failure|Aborted login|LOGIN FAILED|535[ -].*auth|authenticator failed' "$mail_auth_log" 2>/dev/null | extract_source_ips >"$TMPROOT/mail-top-ips.txt" || true
print_ip_table "$TMPROOT/mail-top-ips.txt" "Top source IPs — mail authentication failures"
mail_rate=$(( ${mail_auth_failed:-0} / (DAYS > 0 ? DAYS : 1) ))
if (( mail_rate > 300 )); then
  warn "Высокая интенсивность mail auth failures: около $mail_rate событий/сутки"
fi


section "MAIL FLOW ANALYTICS"
if [[ "$MTA" == "postfix" && -s "$mail_log" && -r "$SCRIPT_DIR/lib/mail_stats.py" ]] && have python3; then
  mail_stats_args=(
    "$SCRIPT_DIR/lib/mail_stats.py"
    --input "$mail_log"
    --from "$AUDIT_FROM"
    --to "$AUDIT_TO"
    --top "$MAIL_TOP"
    --json-output "$MAIL_STATS_JSON"
    --output-dir "$TMPROOT/mail-stats"
  )
  (( REDACT == 1 )) && mail_stats_args+=( --redact )
  if python3 "${mail_stats_args[@]}"; then
    load_mail_stats_summary
    kv "Requested period" "$AUDIT_FROM -> $AUDIT_TO"
    kv "Observed log period" "${MAIL_OBSERVED_FROM:--} -> ${MAIL_OBSERVED_TO:--}"
    kv "Log lines" "${MAIL_LINES_IN_PERIOD:-0} in period / ${MAIL_LINES_SCANNED:-0} scanned"
    kv "Outbound messages" "${MAIL_OUTBOUND_MESSAGES:-0} unique message(s)"
    kv "Authenticated submissions" "${MAIL_AUTH_SUBMISSIONS:-0} accepted message(s)"
    kv "Authenticated delivered" "${MAIL_AUTH_OUTBOUND_MESSAGES:-0} message(s) with successful external delivery"
    kv "Outbound deliveries" "${MAIL_OUTBOUND_DELIVERIES:-0} recipient delivery(s)"
    kv "Incoming messages" "${MAIL_INCOMING_MESSAGES:-0} message(s), ${MAIL_INCOMING_DELIVERIES:-0} delivery(s)"
    kv "Bounced / deferred" "${MAIL_BOUNCED_DELIVERIES:-0} / ${MAIL_DEFERRED_DELIVERIES:-0}"
    kv "Outbound payload" "${MAIL_OUTBOUND_BYTES:-0} byte(s) from Postfix queue metadata"

    print_mailbox_stats_table "$TMPROOT/mail-stats/top-users.tsv" "Top authenticated SMTP users — успешно отправленные сообщения"
    print_mailbox_stats_table "$TMPROOT/mail-stats/top-senders.tsv" "Top envelope senders — успешно отправленные сообщения"
    print_domain_stats_table "$TMPROOT/mail-stats/top-sender-domains.tsv" "Top sender domains — уникальные отправленные сообщения"
    print_domain_stats_table "$TMPROOT/mail-stats/top-recipient-domains.tsv" "Top recipient domains — успешные внешние доставки"
    print_domain_stats_table "$TMPROOT/mail-stats/top-incoming-domains.tsv" "Top incoming domains — локально доставленные сообщения"

    if (( ${MAIL_OUTBOUND_MESSAGES:-0} == 0 && ${MAIL_INCOMING_MESSAGES:-0} == 0 )); then
      warn "В выбранном периоде не найдены связанные Postfix queue + delivery события"
    else
      pass "Mail-flow статистика построена по Queue ID с фильтрацией периода"
    fi
  else
    warn "Не удалось построить расширенную Postfix статистику"
  fi
elif [[ "$MTA" == "postfix" && ! -s "$mail_log" ]]; then
  warn "Postfix обнаружен, но доступные mail logs не найдены"
elif [[ "$MTA" == "postfix" ]]; then
  warn "Для расширенной статистики требуются python3 и lib/mail_stats.py"
else
  info "Mail flow analytics сейчас поддерживает Postfix; для $MTA раздел пропущен"
fi

section "MTA / RELAY CONFIGURATION"
case "$MTA" in
  postfix)
    if have postconf || [[ "$MAIL_PLATFORM" == "mailcow" && -n "${MAILCOW_POSTFIX_CONTAINER:-}" ]]; then
      run_postconf myhostname mydomain myorigin mydestination relay_domains mynetworks mynetworks_style \
        smtpd_relay_restrictions smtpd_recipient_restrictions smtpd_sasl_auth_enable \
        smtpd_tls_security_level smtpd_tls_protocols smtpd_tls_mandatory_protocols \
        smtp_tls_security_level 2>/dev/null || true
      relay_restrictions="$(run_postconf -h smtpd_relay_restrictions 2>/dev/null || true)"
      recipient_restrictions="$(run_postconf -h smtpd_recipient_restrictions 2>/dev/null || true)"
      mynetworks="$(run_postconf -h mynetworks 2>/dev/null || true)"
      if grep -Eq 'reject_unauth_destination|defer_unauth_destination' <<<"$relay_restrictions $recipient_restrictions"; then
        pass "Postfix: найдена защита reject/defer_unauth_destination"
      else
        critical "Postfix: reject_unauth_destination не найден в relay/recipient restrictions"
      fi
      if grep -Eq '(^|[ ,])(0\.0\.0\.0/0|0/0|::/0)([ ,]|$)' <<<"$mynetworks"; then
        critical "Postfix: mynetworks содержит весь IPv4/IPv6 интернет"
      else
        pass "Postfix: явного 0.0.0.0/0 или ::/0 в mynetworks нет"
      fi
    else
      warn "Postfix обнаружен, но postconf недоступен"
    fi
    ;;
  exim)
    exim_bin="$(command -v exim4 || command -v exim || true)"
    if [[ -n "$exim_bin" ]]; then
      "$exim_bin" -bP primary_hostname local_domains relay_to_domains relay_from_hosts auth_advertise_hosts tls_advertise_hosts 2>/dev/null || true
      relay_hosts="$($exim_bin -bP relay_from_hosts 2>/dev/null || true)"
      if grep -Eq '0\.0\.0\.0/0|::/0|\*' <<<"$relay_hosts"; then
        critical "Exim: relay_from_hosts выглядит чрезмерно широким"
      else
        info "Exim: локальная relay-конфигурация выведена; обязательна внешняя open-relay проверка"
      fi
    fi
    ;;
  opensmtpd)
    smtpctl show config 2>/dev/null | sed -n '1,220p' || true
    info "OpenSMTPD: проверь match/action relay rules; обязательна внешняя open-relay проверка"
    ;;
  sendmail)
    sendmail -d0.1 -bv root 2>/dev/null | sed -n '1,80p' || true
    info "Sendmail: локальная конфигурация сложна для надёжной эвристики; обязательна внешняя open-relay проверка"
    ;;
esac
info "Локальный скрипт не может надёжно доказать отсутствие open relay: тест нужен с внешнего недоверенного IP"

section "TLS CERTIFICATES / LOCAL SERVICES"
if have openssl && have timeout && have ss; then
  listening_tcp="$(ss -H -lnt 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -u)"
  grep -qx '443' <<<"$listening_tcp" && probe_tls "HTTPS 443" 443 ""
  grep -qx '465' <<<"$listening_tcp" && probe_tls "SMTPS 465" 465 ""
  grep -qx '993' <<<"$listening_tcp" && probe_tls "IMAPS 993" 993 ""
  grep -qx '995' <<<"$listening_tcp" && probe_tls "POP3S 995" 995 ""
  grep -qx '25'  <<<"$listening_tcp" && probe_tls "SMTP STARTTLS 25" 25 smtp
  grep -qx '587' <<<"$listening_tcp" && probe_tls "Submission STARTTLS 587" 587 smtp
  grep -qx '143' <<<"$listening_tcp" && probe_tls "IMAP STARTTLS 143" 143 imap
  grep -qx '110' <<<"$listening_tcp" && probe_tls "POP3 STARTTLS 110" 110 pop3
else
  warn "Для TLS-проверок требуются openssl, timeout и ss"
fi
if [[ "$IMAP_SERVER" == "dovecot" ]] \
  && { have doveconf || [[ "$MAIL_PLATFORM" == "mailcow" && -n "${MAILCOW_DOVECOT_CONTAINER:-}" ]]; }; then
  run_doveconf -h ssl_min_protocol 2>/dev/null | sed 's/^/Dovecot ssl_min_protocol: /' || true
  run_doveconf -h ssl 2>/dev/null | sed 's/^/Dovecot ssl: /' || true
fi

if (( DEEP == 1 )) && have openssl && have ss; then
  section "DEEP TLS LEGACY PROTOCOL CHECK"
  for port in 443 465 993 995; do
    ss -H -lnt 2>/dev/null | awk '{print $4}' | grep -Eq ":${port}$" || continue
    if timeout 8 openssl s_client -connect "127.0.0.1:$port" -servername "$MAIL_HOST" -tls1 </dev/null 2>/dev/null | grep -q 'Protocol  *: TLSv1'; then
      warn "Порт $port принимает TLS 1.0"
    else
      pass "Порт $port не принял TLS 1.0"
    fi
  done
fi

section "DNS / MAIL AUTHENTICATION RECORDS"
if [[ -n "$MAIL_DOMAIN" ]]; then
  if have dig; then
    echo "-- MX --"; dig +short MX "$MAIL_DOMAIN" || true
    echo "-- A/AAAA for $MAIL_HOST --"; dig +short A "$MAIL_HOST" || true; dig +short AAAA "$MAIL_HOST" || true
    spf="$(dig +short TXT "$MAIL_DOMAIN" | tr -d '"' | grep -i 'v=spf1' || true)"
    dmarc="$(dig +short TXT "_dmarc.$MAIL_DOMAIN" | tr -d '"' | grep -i 'v=DMARC1' || true)"
    mta_sts="$(dig +short TXT "_mta-sts.$MAIL_DOMAIN" | tr -d '"' | grep -i 'v=STSv1' || true)"
    tls_rpt="$(dig +short TXT "_smtp._tls.$MAIL_DOMAIN" | tr -d '"' | grep -i 'v=TLSRPTv1' || true)"
    if [[ -n "$spf" ]]; then
      echo "SPF: $spf"
      spf_count="$(grep -c . <<<"$spf")"
      if (( spf_count > 1 )); then
        critical "Опубликовано несколько SPF-записей: $spf_count"
      else
        pass "SPF опубликован одной записью"
      fi
    else
      warn "SPF для $MAIL_DOMAIN не найден"
    fi
    if [[ -n "$dmarc" ]]; then
      echo "DMARC: $dmarc"
      dmarc_policy="$(sed -nE 's/.*(^|;[[:space:]]*)p=([^;[:space:]]+).*/\2/ip' <<<"$dmarc" | head -1 | tr '[:upper:]' '[:lower:]')"
      case "$dmarc_policy" in
        reject) pass "DMARC policy=reject" ;;
        quarantine) pass "DMARC policy=quarantine" ;;
        none) warn "DMARC policy=none: включён только мониторинг" ;;
        *) warn "DMARC опубликован, но policy p= не распознана" ;;
      esac
    else
      warn "DMARC для $MAIL_DOMAIN не найден"
    fi
    if [[ -n "$DKIM_SELECTOR" ]]; then
      dkim="$(dig +short TXT "$DKIM_SELECTOR._domainkey.$MAIL_DOMAIN" | tr -d '"' || true)"
      if [[ "$dkim" == *"v=DKIM1"* || "$dkim" == *"p="* ]]; then
        echo "DKIM: $dkim"
        pass "DKIM опубликован"
        dkim_key="$(sed -nE 's/.*(^|;[[:space:]]*)p=([^;[:space:]]+).*/\2/p' <<<"$dkim" | head -1)"
        if [[ -n "$dkim_key" ]] && have base64 && have openssl; then
          if printf '%s' "$dkim_key" | base64 -d >"$TMPROOT/dkim-key.der" 2>/dev/null; then
            dkim_key_info="$(openssl pkey -pubin -inform DER -in "$TMPROOT/dkim-key.der" -text -noout 2>/dev/null | head -1 || true)"
            echo "DKIM key: ${dkim_key_info:-format not recognized}"
            dkim_bits="$(sed -nE 's/.*Public-Key: \(([0-9]+) bit\).*/\1/p' <<<"$dkim_key_info")"
            if [[ "$dkim_bits" =~ ^[0-9]+$ ]] && (( dkim_bits < 1024 )); then
              critical "DKIM RSA key слишком короткий: $dkim_bits bit"
            elif [[ "$dkim_bits" =~ ^[0-9]+$ ]] && (( dkim_bits < 2048 )); then
              warn "DKIM RSA key короче рекомендуемых 2048 bit: $dkim_bits bit"
            elif [[ "$dkim_bits" =~ ^[0-9]+$ ]]; then
              pass "DKIM RSA key length: $dkim_bits bit"
            elif [[ "$dkim_key_info" == *ED25519* ]]; then
              pass "DKIM использует Ed25519 key"
            fi
          fi
        fi
      else
        warn "DKIM не найден для selector=$DKIM_SELECTOR"
      fi
    else
      info "DKIM не проверялся: selector не задан"
    fi
    if [[ -n "$mta_sts" ]]; then
      echo "MTA-STS: $mta_sts"
      pass "MTA-STS TXT record опубликован"
    else
      info "MTA-STS TXT record не найден"
    fi
    if [[ -n "$tls_rpt" ]]; then
      echo "TLS-RPT: $tls_rpt"
      pass "SMTP TLS Reporting опубликован"
    else
      info "SMTP TLS Reporting record не найден"
    fi
    for ip in $(dig +short A "$MAIL_HOST" 2>/dev/null); do
      ptr="$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//' | head -1)"
      if [[ -n "$ptr" ]]; then
        echo "PTR $ip -> $ptr"
        if [[ "$ptr" == "$MAIL_HOST" ]]; then
          pass "PTR совпадает с $MAIL_HOST"
        else
          warn "PTR $ip указывает на $ptr, а не $MAIL_HOST"
        fi
      else
        warn "PTR для $ip отсутствует"
      fi
    done
  else
    warn "dig не найден; DNS-проверки пропущены"
  fi
else
  info "Для MX/SPF/DMARC передай --domain example.com"
fi

section "LOCAL USERS / PRIVILEGES"
uid0_accounts="$(awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')"
uid0_count="$(awk -F: '$3==0{c++} END{print c+0}' /etc/passwd 2>/dev/null)"
echo "UID 0 accounts: ${uid0_accounts:-unknown}"
if (( uid0_count > 1 )); then critical "Найдено более одного UID 0 аккаунта"; else pass "UID 0 принадлежит одному аккаунту"; fi

echo "-- Interactive-shell accounts --"
awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {printf "%-24s uid=%-6s home=%-28s shell=%s\n",$1,$3,$6,$7}' /etc/passwd 2>/dev/null || true

if [[ -r /etc/shadow ]]; then
  empty_passwords="$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')"
  if [[ -n "$empty_passwords" ]]; then
    critical "Аккаунты с пустым password hash: $empty_passwords"
  else
    pass "Пустых password hash не найдено"
  fi
fi

echo "-- sudo NOPASSWD entries --"
grep -RhsE '^[[:space:]]*[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null || true

section "SSH AUTHORIZED_KEYS"
keys_found=0
while IFS= read -r keyfile; do
  keys_found=1
  mode="$(stat -c '%a' "$keyfile" 2>/dev/null || echo '?')"
  owner="$(stat -c '%U:%G' "$keyfile" 2>/dev/null || echo '?')"
  lines="$(grep -Ec '^[[:space:]]*(ssh-|ecdsa-|sk-|cert-authority|restrict|from=|command=)' "$keyfile" 2>/dev/null || true)"
  echo "$keyfile owner=$owner mode=$mode key-lines=$lines"
  case "$mode" in
    600|400) pass "Корректные права на $keyfile" ;;
    *) warn "Проверь права на $keyfile: mode=$mode" ;;
  esac
done < <(find /root /home -xdev -type f -name authorized_keys 2>/dev/null | sort)
(( keys_found == 0 )) && info "authorized_keys не найдены"

section "DISK / FILESYSTEM CAPACITY"
echo "-- Filesystem capacity --"
df -hPT -x tmpfs -x devtmpfs 2>/dev/null || df -hP 2>/dev/null || true
check_usage_table "Filesystem" < <(df -P -x tmpfs -x devtmpfs 2>/dev/null | tail -n +2)
echo "-- Inodes --"
df -iPT -x tmpfs -x devtmpfs 2>/dev/null || true
check_usage_table "Inode" < <(df -Pi -x tmpfs -x devtmpfs 2>/dev/null | tail -n +2)

mail_storage_path="$(detect_mail_storage_path | head -1)"
if [[ -n "$mail_storage_path" && -e "$mail_storage_path" ]]; then
  echo "-- Mail storage filesystem --"
  kv "Mail storage path" "$mail_storage_path"
  df -hPT "$mail_storage_path" 2>/dev/null || true
  if (( DEEP == 1 )); then
    timeout 120 du -shx -- "$mail_storage_path" 2>/dev/null | sed 's/^/Mail storage apparent usage: /' || true
  fi
else
  info "Путь mailbox storage автоматически не определён"
fi

section "MAIL QUEUE"
case "$MTA" in
  postfix)
    postfix_queue_output="$TMPROOT/postfix-queue.txt"
    : >"$postfix_queue_output"
    if [[ "$MAIL_PLATFORM" == "mailcow" && -n "${MAILCOW_POSTFIX_CONTAINER:-}" ]]; then
      timeout 20 docker exec "$MAILCOW_POSTFIX_CONTAINER" postqueue -p >"$postfix_queue_output" 2>/dev/null || true
    elif have postqueue; then
      postqueue -p >"$postfix_queue_output" 2>/dev/null || true
    fi
    if [[ -s "$postfix_queue_output" ]]; then
      tail -n 20 "$postfix_queue_output" || true
      queue_count="$(grep -Ec '^[A-F0-9]+[*!]?[[:space:]]' "$postfix_queue_output" || true)"
      echo "Approx. queued messages: $queue_count"
      if (( queue_count > 1000 )); then
        critical "Очень большая Postfix queue: $queue_count"
      elif (( queue_count > 100 )); then
        warn "Большая Postfix queue: $queue_count"
      else
        pass "Размер Postfix queue не выглядит аварийным"
      fi
    else
      warn "Postfix queue недоступна для чтения"
    fi
    ;;
  exim)
    exim_bin="$(command -v exim4 || command -v exim || true)"
    if [[ -n "$exim_bin" ]]; then
      queue_count="$($exim_bin -bpc 2>/dev/null || echo '?')"
      echo "Queued messages: $queue_count"
      if [[ "$queue_count" =~ ^[0-9]+$ ]]; then
        if (( queue_count > 1000 )); then
          critical "Очень большая Exim queue: $queue_count"
        elif (( queue_count > 100 )); then
          warn "Большая Exim queue: $queue_count"
        fi
      fi
    fi
    ;;
  sendmail)
    if have mailq; then
      mailq 2>/dev/null | tail -n 40 || true
    fi
    ;;
esac

section "SUID / SGID"
echo "-- SUID files in standard paths --"
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt \
  -xdev -type f -perm -4000 -printf '%m %u:%g %p\n' 2>/dev/null | sort
suspicious_suid="$(find /home /root /tmp /var/tmp /dev/shm -xdev -type f -perm -4000 -print 2>/dev/null || true)"
if [[ -n "$suspicious_suid" ]]; then
  critical "SUID-файлы найдены в пользовательских или временных каталогах"
  printf '%s\n' "$suspicious_suid"
else
  pass "SUID в /home,/root,/tmp,/var/tmp,/dev/shm не найден"
fi
if (( DEEP == 1 )); then
  echo "-- Full filesystem SUID and executable SGID scan --"
  find / -xdev -type f \
    \( -perm -4000 -o \( -perm -2000 -perm /0111 \) \) \
    -printf '%m %u:%g %p\n' 2>/dev/null | sort
fi

section "WORLD-WRITABLE SENSITIVE PATHS"
world_writable="$(find /etc /usr/local /opt -xdev \( -type f -o -type d \) -perm -0002 -print 2>/dev/null | head -100)"
if [[ -n "$world_writable" ]]; then
  warn "Найдены world-writable объекты в /etc, /usr/local или /opt"
  printf '%s\n' "$world_writable"
else
  pass "World-writable объектов в /etc, /usr/local и /opt не найдено"
fi

section "FAILED SERVICES / SECURITY FRAMEWORK"
if have systemctl; then
  failed_units="$(systemctl --failed --no-legend --plain 2>/dev/null || true)"
  if [[ -n "$failed_units" ]]; then
    echo "$failed_units"
    warn "Есть failed systemd units"
  else
    pass "Failed systemd units отсутствуют"
  fi
fi
if have aa-status; then
  aa-status 2>/dev/null | sed -n '1,80p' || true
elif have getenforce; then
  selinux_state="$(getenforce 2>/dev/null || true)"
  echo "SELinux: $selinux_state"
  if [[ "$selinux_state" == "Enforcing" ]]; then
    pass "SELinux enforcing"
  else
    warn "SELinux не в Enforcing"
  fi
else
  info "AppArmor/SELinux status tool не найден"
fi

section "CRON / SYSTEMD TIMERS"
echo "-- /etc/cron.d --"
find /etc/cron.d -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | sort || true
echo "-- User crontabs --"
while IFS=: read -r user _ _ _ _ _ shell; do
  [[ "$shell" =~ (nologin|false)$ ]] && continue
  cron="$(crontab -u "$user" -l 2>/dev/null || true)"
  active_cron="$(printf '%s\n' "$cron" | grep -Ev '^[[:space:]]*(#|$)' || true)"
  [[ -n "$active_cron" ]] || continue
  cron_count="$(printf '%s\n' "$active_cron" | wc -l | tr -d ' ')"
  echo "[$user] active entries=$cron_count"
  if (( DEEP == 1 )); then
    printf '%s\n' "$active_cron" \
      | sed -E \
          -e 's#(https?://)[^/@[:space:]]+:[^/@[:space:]]+@#\1<redacted>@#g' \
          -e 's/((PASS|PASSWORD|TOKEN|SECRET|API_KEY|ACCESS_KEY)[A-Za-z0-9_]*=)[^[:space:]]+/\1<redacted>/Ig'
  fi
done </etc/passwd
echo "-- systemd timers --"
systemctl list-timers --all --no-pager 2>/dev/null || true

echo "-- custom units in /etc/systemd/system --"
find /etc/systemd/system -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \) -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort || true

section "BACKUP DETECTION"
backup_paths="$TMPROOT/backup-paths.txt"
: >"$backup_paths"
for tool in restic borg borgmatic rclone duplicity rsnapshot bacula-fd urbackupclientctl; do
  have "$tool" && echo "binary:$tool=$(command -v "$tool")" >>"$backup_paths"
done
find /etc/systemd/system /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly \
  -type f 2>/dev/null | while IFS= read -r f; do
    base="$(basename "$f")"
    if grep -IqiE 'restic|borgmatic|borg( |$)|rclone|duplicity|rsnapshot|bacula|urbackup' "$f" 2>/dev/null \
       || [[ "$base" =~ [Bb]ackup ]]; then
      echo "job:$f"
    fi
  done >>"$backup_paths"
sort -u "$backup_paths" | sed -n '1,100p'
if [[ -s "$backup_paths" ]]; then
  info "Обнаружены локальные признаки backup tooling/jobs; успешность и restore отдельно не подтверждены"
else
  warn "Локальные backup jobs не обнаружены; проверь внешний backup и тест восстановления"
fi

section "LAST LOGINS"
last -a -n 20 2>/dev/null || true
echo "-- Failed logins --"
lastb -a -n 20 2>/dev/null || true

if (( DEEP == 1 )); then
  section "DEEP PACKAGE INTEGRITY"
  if have debsums; then
    debsums -s 2>/dev/null || true
    info "debsums завершён; любой вывод требует ручной проверки"
  elif have rpm; then
    rpm -Va 2>/dev/null | sed -n '1,300p' || true
    info "rpm -Va завершён; конфигурационные изменения могут быть легитимны"
  else
    info "debsums/rpm integrity checker недоступен"
  fi

  section "RECENTLY MODIFIED EXECUTABLE / CONFIG PATHS"
  find /usr/local/bin /usr/local/sbin /opt /etc/systemd/system /etc/cron.d \
    -xdev -type f -mtime -30 -printf '%TY-%Tm-%Td %TH:%TM %m %u:%g %p\n' 2>/dev/null | sort -r | sed -n '1,300p'
fi

section "SUMMARY"
printf '  %s%-12s%s %5d    %s%-12s%s %5d    %s%-12s%s %5d    %s%-12s%s %5d\n' \
  "$GREEN" "OK" "$RESET" "$PASSES" "$BLUE" "INFO" "$RESET" "$INFOS" \
  "$YELLOW" "WARN" "$RESET" "$WARNINGS" "$RED" "FAIL" "$RESET" "$CRITICALS"

if (( CRITICALS > 0 )); then
  AUDIT_RC=2; printf '\n%s  RESULT: CRITICAL — сначала исправь FAIL, затем WARN%s\n' "$RED$BOLD" "$RESET"
elif (( WARNINGS > 0 )); then
  AUDIT_RC=1; printf '\n%s  RESULT: REVIEW REQUIRED — критических проблем нет%s\n' "$YELLOW$BOLD" "$RESET"
else
  AUDIT_RC=0; printf '\n%s  RESULT: CLEAN — явных проблем не найдено%s\n' "$GREEN$BOLD" "$RESET"
fi

if (( INTERACTIVE == 1 )); then
  interactive_ban_menu
else
  info "Управление блокировками не запускалось. Для меню: --interactive"
fi

if [[ "$OUTPUT_FORMAT" == "json" ]]; then
  exec 1>&3 2>&4
  python3 - "$FINDINGS_FILE" "$MAIL_STATS_JSON" "$SCRIPT_VERSION" "$MAIL_HOST" "$MAIL_DOMAIN" \
    "$MAIL_PLATFORM" "$PLATFORM_VERSION" "$AUDIT_FROM" "$AUDIT_TO" "$PASSES" "$INFOS" \
    "$WARNINGS" "$CRITICALS" "$AUDIT_RC" "$REDACT" >"$TMPROOT/report.json" <<'PYREPORT'
import json
import os
import re
import subprocess
import sys

(
    findings_path, mail_stats_path, version, host, domain, platform, platform_version,
    audit_from, audit_to, passes, infos, warnings, criticals, exit_code, redact
) = sys.argv[1:]

redact = redact == "1"
email_re = re.compile(r"[\w.%+-]+@[\w.-]+")
ipv4_re = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
ipv6_re = re.compile(r"(?:(?:[0-9A-Fa-f]{0,4}):){2,7}[0-9A-Fa-f]{0,4}")


def clean(value):
    if not redact or not isinstance(value, str):
        return value
    value = email_re.sub("<redacted-email>", value)
    value = ipv4_re.sub("<redacted-ip>", value)
    return ipv6_re.sub("<redacted-ipv6>", value)


findings = []
remediation_by_section = {
    "PATCH": "Install reviewed security updates and schedule a controlled reboot when required.",
    "STACK": "Restore the affected mail service or container and inspect its logs before accepting traffic.",
    "SSH": "Harden the effective sshd configuration and validate access in a second session before reloading.",
    "NET": "Confirm the listener is required and restrict it with bind addresses and firewall policy.",
    "FW": "Enable and verify a default-deny host firewall policy without interrupting active administration.",
    "BRUTE": "Enable a tested brute-force protection policy and verify mail and SSH jails.",
    "FLOW": "Verify log retention, Postfix Queue ID visibility, and the selected audit period.",
    "MTA": "Review relay restrictions from an external untrusted host before changing production configuration.",
    "TLS": "Renew or replace the certificate and enforce TLS 1.2 or newer.",
    "DNS": "Correct the DNS record, wait for propagation, and repeat the external verification.",
    "DISK": "Free or extend capacity and confirm mail queues and mailbox storage can continue growing safely.",
    "QUEUE": "Inspect deferred reasons and remediate delivery failures before deleting or requeuing mail.",
    "BACKUP": "Configure an off-host backup and perform a documented restore test.",
}
with open(findings_path, encoding="utf-8", errors="replace") as handle:
    for line in handle:
        parts = line.rstrip("\n").split("\t", 2)
        if len(parts) == 3:
            section = parts[0].split("-", 1)[0]
            findings.append({
                "id": parts[0], "severity": parts[1], "message": clean(parts[2]),
                "remediation": remediation_by_section.get(section) if parts[1] in {"warning", "critical"} else None,
            })

mail_statistics = None
if os.path.isfile(mail_stats_path):
    with open(mail_stats_path, encoding="utf-8") as handle:
        mail_statistics = json.load(handle)

filesystems = []
try:
    output = subprocess.run(
        ["df", "-P", "-B1", "-x", "tmpfs", "-x", "devtmpfs"],
        check=False, capture_output=True, text=True, timeout=15,
    ).stdout.splitlines()[1:]
    for line in output:
        parts = line.split(None, 5)
        if len(parts) == 6 and parts[1].isdigit():
            filesystems.append({
                "filesystem": clean(parts[0]), "bytes_total": int(parts[1]),
                "bytes_used": int(parts[2]), "bytes_available": int(parts[3]),
                "used_percent": int(parts[4].rstrip("%")), "mountpoint": clean(parts[5]),
            })
except (OSError, subprocess.TimeoutExpired, ValueError):
    pass

status = "critical" if int(criticals) else "review_required" if int(warnings) else "clean"
report = {
    "schema_version": 1,
    "tool": {"name": "mail-sec-audit", "version": version},
    "generated_at": __import__("datetime").datetime.now().astimezone().isoformat(),
    "target": {
        "host": "<redacted-host>" if redact else host,
        "domain": "<redacted-domain>" if redact and domain else domain or None,
        "platform": platform,
        "platform_version": platform_version or None,
    },
    "period": {"from": audit_from, "to": audit_to},
    "result": {
        "status": status, "exit_code": int(exit_code),
        "counts": {"pass": int(passes), "info": int(infos), "warning": int(warnings), "critical": int(criticals)},
    },
    "findings": findings,
    "mail_statistics": mail_statistics,
    "filesystems": filesystems,
}
print(json.dumps(report, ensure_ascii=False, indent=2))
PYREPORT

  if [[ -n "$REPORT_FILE" && "$APPEND_REPORT" -eq 1 ]]; then
    tee -a -- "$REPORT_FILE" <"$TMPROOT/report.json"
  elif [[ -n "$REPORT_FILE" ]]; then
    tee -- "$REPORT_FILE" <"$TMPROOT/report.json"
  else
    cat "$TMPROOT/report.json"
  fi
fi

exit "$AUDIT_RC"
