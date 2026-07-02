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

VERSION="2.2.3"
DAYS=7
MAIL_TOP=20
MAIL_HOST=""
MAIL_DOMAIN=""
DKIM_SELECTOR=""
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
  --hostname FQDN       Основное имя почтового сервера для TLS-проверок
  --domain DOMAIN       Почтовый домен для MX/SPF/DMARC-проверок
  --dkim-selector SEL   DKIM-селектор для DNS-проверки
  --deep                Дополнительные, более тяжёлые проверки
  --report FILE         Одновременно сохранить вывод в файл
  --interactive         После аудита открыть безопасное меню Fail2ban
  --verbose             Показывать полный сырой вывод firewall/listeners
  --no-color            Отключить ANSI-цвета
  -h, --help            Показать справку

Дополнительные разрешённые публичные порты:
  MAIL_AUDIT_ALLOWED_PORTS="10050 9100" sudo bash mail-sec-audit.sh

По умолчанию скрипт полностью read-only. Изменения возможны только в явно включённом
режиме --interactive и только после подтверждения каждой операции.
USAGE
}

while (($#)); do
  case "$1" in
    --days)
      [[ ${2:-} =~ ^[0-9]+$ ]] || { echo "Ошибка: --days требует целое число" >&2; exit 64; }
      DAYS="$2"; shift 2 ;;
    --mail-top)
      [[ ${2:-} =~ ^[0-9]+$ ]] && (( ${2:-0} >= 1 && ${2:-0} <= 100 )) || { echo "Ошибка: --mail-top требует число от 1 до 100" >&2; exit 64; }
      MAIL_TOP="$2"; shift 2 ;;
    --hostname)
      MAIL_HOST="${2:-}"; shift 2 ;;
    --domain)
      MAIL_DOMAIN="${2:-}"; shift 2 ;;
    --dkim-selector)
      DKIM_SELECTOR="${2:-}"; shift 2 ;;
    --deep)
      DEEP=1; shift ;;
    --report)
      REPORT_FILE="${2:-}"; shift 2 ;;
    --interactive|--manage-bans)
      INTERACTIVE=1; shift ;;
    --verbose)
      VERBOSE=1; shift ;;
    --no-color)
      NO_COLOR=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Неизвестная опция: $1" >&2
      usage >&2
      exit 64 ;;
  esac
done

if [[ -n "$REPORT_FILE" ]]; then
  mkdir -p "$(dirname "$REPORT_FILE")" 2>/dev/null || true
  touch "$REPORT_FILE" 2>/dev/null || { echo "Не удалось создать report: $REPORT_FILE" >&2; exit 73; }
  chmod 600 "$REPORT_FILE" 2>/dev/null || true
  exec > >(tee -a "$REPORT_FILE") 2>&1
fi

if [[ -t 1 && "$NO_COLOR" -eq 0 ]]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[1;31m'; YELLOW=$'\033[1;33m'
  GREEN=$'\033[1;32m'; BLUE=$'\033[1;34m'; CYAN=$'\033[1;36m'
  MAGENTA=$'\033[1;35m'; WHITE=$'\033[1;37m'; RESET=$'\033[0m'
else
  BOLD=""; DIM=""; RED=""; YELLOW=""; GREEN=""; BLUE=""; CYAN=""
  MAGENTA=""; WHITE=""; RESET=""
fi

hr() { local line; printf -v line '%*s' "${COLUMNS:-88}" ''; printf '%s%s%s\n' "$DIM" "${line// /─}" "$RESET"; }
banner() {
  printf '\n%s' "$CYAN$BOLD"; hr
  printf '  MAIL SECURITY AUDIT  v%s\n' "$VERSION"
  printf '  host: %-40s period: %s day(s)\n' "$MAIL_HOST" "$DAYS"
  hr; printf '%s' "$RESET"
}
section() {
  SECTION_NO=$((SECTION_NO+1))
  printf '\n%s[%02d] %-68s%s\n' "$BOLD$CYAN" "$SECTION_NO" "$1" "$RESET"
  local line; printf -v line '%*s' "${COLUMNS:-88}" ''; printf '%s%s%s\n' "$DIM" "${line// /─}" "$RESET"
}
pass()     { printf '%s[  OK  ]%s %s\n' "$GREEN" "$RESET" "$*"; ((PASSES+=1)); }
info()     { printf '%s[ INFO ]%s %s\n' "$BLUE" "$RESET" "$*"; ((INFOS+=1)); }
warn()     { printf '%s[ WARN ]%s %s\n' "$YELLOW" "$RESET" "$*"; ((WARNINGS+=1)); }
critical() { printf '%s[ FAIL ]%s %s\n' "$RED" "$RESET" "$*"; ((CRITICALS+=1)); }
have()     { command -v "$1" >/dev/null 2>&1; }
kv()       { printf '  %s%-24s%s %s\n' "$DIM" "$1" "$RESET" "$2"; }

TMPROOT="$(mktemp -d /tmp/mail-sec-audit.XXXXXX)" || exit 1
trap 'rm -rf "$TMPROOT"' EXIT

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
    journalctl --since "$DAYS days ago" --no-pager -o cat "${args[@]}" >"$outfile" 2>/dev/null || true
  fi
}

collect_fallback_logs() {
  local outfile="$1"; shift
  : >"$outfile"
  local pattern f
  for pattern in "$@"; do
    for f in $pattern; do
      [[ -e "$f" ]] || continue
      if have zgrep; then
        zgrep -h '' "$f" >>"$outfile" 2>/dev/null || true
      else
        case "$f" in *.gz) ;; *) cat "$f" >>"$outfile" 2>/dev/null || true ;; esac
      fi
    done
  done
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

valid_ip() {
  local ip="$1"
  if have python3; then
    python3 - "$ip" <<'PYIP' >/dev/null 2>&1
import ipaddress, sys
ipaddress.ip_address(sys.argv[1])
PYIP
  else
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$ip" == *:* ]]
  fi
}

unsafe_to_ban() {
  local ip="$1" current="${SSH_CONNECTION:-}" own
  current="${current%% *}"
  [[ -n "$current" && "$ip" == "$current" ]] && return 0
  for own in $(hostname -I 2>/dev/null || true); do [[ "$ip" == "$own" ]] && return 0; done
  if have python3; then
    python3 - "$ip" <<'PYIP' >/dev/null 2>&1
import ipaddress, sys
x=ipaddress.ip_address(sys.argv[1])
raise SystemExit(0 if (x.is_loopback or x.is_private or x.is_link_local or x.is_multicast or x.is_unspecified) else 1)
PYIP
    return $?
  fi
  [[ "$ip" == 127.* || "$ip" == 10.* || "$ip" == 192.168.* || "$ip" == ::1 ]]
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
  local answer i
  mapfile -t CANDIDATE_LINES < <(cat "$TMPROOT/ssh-top-ips.txt" "$TMPROOT/mail-top-ips.txt" 2>/dev/null \
    | awk '{sum[$2]+=$1} END {for (ip in sum) print sum[ip],ip}' | sort -rn | head -15)
  printf '\n%sКандидаты из текущего отчёта:%s\n' "$BOLD" "$RESET"
  for i in "${!CANDIDATE_LINES[@]}"; do
    printf '  %s%2d)%s %-7s %s\n' "$CYAN" "$((i+1))" "$RESET" ${CANDIDATE_LINES[$i]}
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
  have fail2ban-client && fail2ban-client ping 2>/dev/null | grep -qi pong \
    || { warn "Fail2ban недоступен — меню управления не открыто"; return; }

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
  local mode="$1"
  while read -r filesystem blocks used available percent mountpoint; do
    [[ "$percent" =~ ^[0-9]+%$ ]] || continue
    local value="${percent%%%}"
    if (( value >= 95 )); then
      critical "$mode заполнение $percent: $mountpoint ($filesystem)"
    elif (( value >= 85 )); then
      warn "$mode заполнение $percent: $mountpoint ($filesystem)"
    fi
  done
}

probe_tls() {
  local label="$1" port="$2" starttls="${3:-}" outfile="$TMPROOT/tls-${port}-${starttls:-plain}.txt"
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


print_domain_table() {
  local file="$1" title="$2" count domain rank=0 color
  printf '%s%s%s\n' "$BOLD" "$title" "$RESET"
  printf '  %s%-4s %-10s %s%s\n' "$DIM" "#" "MESSAGES" "DOMAIN" "$RESET"
  while read -r count domain; do
    [[ "$count" =~ ^[0-9]+$ && -n "$domain" ]] || continue
    rank=$((rank+1))
    if (( rank <= 3 )); then color="$CYAN"; else color="$WHITE"; fi
    printf '  %s%-4d %-10s %s%s\n' "$color" "$rank" "$count" "$domain" "$RESET"
  done < <(head -n "$MAIL_TOP" "$file" 2>/dev/null)
  (( rank == 0 )) && printf '  %sнет данных%s\n' "$DIM" "$RESET"
}

analyze_postfix_mail_flow() {
  local logfile="$1" outdir="$2"
  : >"$outdir/incoming-domains.txt"
  : >"$outdir/outgoing-domains.txt"
  : >"$outdir/mail-flow-summary.txt"

  awk -v incoming_file="$outdir/incoming.raw" \
      -v outgoing_file="$outdir/outgoing.raw" \
      -v summary_file="$outdir/mail-flow-summary.txt" '
    function clean_domain(addr, d) {
      d=tolower(addr)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", d)
      gsub(/^<|>$/, "", d)
      if (d == "" || d == "-" || d == "mailer-daemon" || d !~ /@/) return ""
      sub(/^.*@/, "", d)
      sub(/[>;,].*$/, "", d)
      gsub(/^\[|\]$/, "", d)
      return d
    }
    {
      qid=""
      if (match($0, /[A-F0-9][A-F0-9][A-F0-9][A-F0-9][A-F0-9]+: /)) {
        qid=substr($0, RSTART, RLENGTH-2)
      }
    }
    /postfix\/qmgr/ && / from=<[^>]*>/ {
      if (qid != "" && match($0, / from=<[^>]*>/)) {
        sender=substr($0, RSTART+7, RLENGTH-8)
        from_addr[qid]=sender
      }
      next
    }
    /postfix\/(smtp|lmtp|local|virtual|pipe)/ && / status=sent/ {
      recipient=""
      if (match($0, / to=<[^>]*>/)) recipient=substr($0, RSTART+5, RLENGTH-6)
      from_domain=(qid in from_addr ? clean_domain(from_addr[qid]) : "")
      to_domain=clean_domain(recipient)

      if ($0 ~ /postfix\/smtp/) {
        if (to_domain != "") {
          print to_domain >> outgoing_file
          outgoing++
        }
      } else if ($0 ~ /postfix\/(lmtp|local|virtual|pipe)/) {
        if (from_domain != "") {
          print from_domain >> incoming_file
          incoming++
        }
      }
    }
    END {
      print "incoming=" (incoming+0) > summary_file
      print "outgoing=" (outgoing+0) >> summary_file
    }
  ' "$logfile" 2>/dev/null || true

  if [[ -s "$outdir/incoming.raw" ]]; then
    sort "$outdir/incoming.raw" | uniq -c | sort -rn >"$outdir/incoming-domains.txt"
  fi
  if [[ -s "$outdir/outgoing.raw" ]]; then
    sort "$outdir/outgoing.raw" | uniq -c | sort -rn >"$outdir/outgoing-domains.txt"
  fi
}

banner
section "AUDIT CONTEXT"
kv "Date" "$(date --iso-8601=seconds 2>/dev/null || date)"
kv "Host" "$(hostname 2>/dev/null || true)"
kv "FQDN / TLS name" "$MAIL_HOST"
kv "Mail domain" "${MAIL_DOMAIN:-(not specified)}"
kv "Analysis period" "$DAYS day(s)"
kv "Kernel" "$(uname -srmo 2>/dev/null || uname -a)"
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  kv "OS" "${PRETTY_NAME:-unknown}"
fi
if (( EUID == 0 )); then
  pass "Запущено от root: доступны все локальные проверки"
else
  warn "Запущено не от root: часть данных будет недоступна"
fi
[[ "$MAIL_HOST" == *.* ]] && pass "Hostname выглядит как FQDN" || warn "Hostname '$MAIL_HOST' не выглядит как FQDN"

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
      (( age_days > 7 )) && warn "APT metadata старше 7 дней: ${age_days} дн.; число обновлений может быть неточным" \
                        || info "Возраст APT metadata: ${age_days} дн."
    fi
  fi
  if have apt-config; then
    apt-config dump 2>/dev/null | grep -E 'APT::Periodic::(Enable|Update-Package-Lists|Unattended-Upgrade)' || true
  fi
elif have dnf; then
  dnf_output="$TMPROOT/dnf-check.txt"
  timeout 120 dnf -q check-update >"$dnf_output" 2>/dev/null || rc=$?
  rc="${rc:-0}"
  updates="$(awk 'NF>=3 && $1 !~ /^(Last|Obsoleting|Security:|$)/ {c++} END{print c+0}' "$dnf_output")"
  echo "Pending packages: $updates"
  (( updates > 0 )) && warn "Есть доступные DNF-обновления: $updates" || pass "DNF не сообщил доступных обновлений"
elif have yum; then
  yum_output="$TMPROOT/yum-check.txt"
  timeout 120 yum -q check-update >"$yum_output" 2>/dev/null || true
  updates="$(awk 'NF>=3 && $1 !~ /^(Loaded|Security:|$)/ {c++} END{print c+0}' "$yum_output")"
  echo "Pending packages: $updates"
  (( updates > 0 )) && warn "Есть доступные YUM-обновления: $updates" || pass "YUM не сообщил доступных обновлений"
else
  info "Поддерживаемый пакетный менеджер не найден"
fi

if [[ -f /var/run/reboot-required ]]; then
  warn "Требуется перезагрузка: $(tr '\n' ' ' </var/run/reboot-required.pkgs 2>/dev/null || true)"
else
  pass "Маркер reboot-required отсутствует"
fi

section "MAIL STACK DETECTION"
if systemctl is-active --quiet postfix.service 2>/dev/null; then
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

echo "Detected MTA:        $MTA"
echo "Detected IMAP/POP3:  $IMAP_SERVER"

if have systemctl; then
  for unit in postfix.service exim4.service exim.service sendmail.service opensmtpd.service \
              dovecot.service courier-imap.service courier-pop.service rspamd.service \
              spamassassin.service amavis.service clamav-daemon.service clamd@scan.service \
              opendkim.service opendmarc.service nginx.service apache2.service httpd.service \
              fail2ban.service; do
    is_systemd_unit_known "$unit" && unit_state_line "$unit"
  done
fi

case "$MTA" in
  postfix)
    systemctl is-active --quiet postfix 2>/dev/null && pass "Postfix активен" || critical "Postfix обнаружен, но не active"
    ;;
  exim)
    if systemctl is-active --quiet exim4 2>/dev/null || systemctl is-active --quiet exim 2>/dev/null; then
      pass "Exim активен"
    else
      critical "Exim обнаружен, но не active"
    fi
    ;;
  opensmtpd)
    systemctl is-active --quiet opensmtpd 2>/dev/null && pass "OpenSMTPD активен" || critical "OpenSMTPD обнаружен, но не active"
    ;;
  sendmail)
    systemctl is-active --quiet sendmail 2>/dev/null && pass "Sendmail активен" || warn "Sendmail обнаружен, но systemd не подтверждает active"
    ;;
  none)
    critical "MTA не обнаружен"
    ;;
esac

if [[ "$IMAP_SERVER" == "dovecot" ]]; then
  systemctl is-active --quiet dovecot 2>/dev/null && pass "Dovecot активен" || critical "Dovecot обнаружен, но не active"
elif [[ "$IMAP_SERVER" == "courier" ]]; then
  systemctl is-active --quiet courier-imap 2>/dev/null && pass "Courier IMAP активен" || warn "Courier обнаружен, но не active"
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
  [[ "$pass_auth" == "yes" ]] && warn "SSH: PasswordAuthentication=yes" || pass "SSH: password authentication отключена"
  [[ "$pubkey_auth" == "yes" ]] && pass "SSH: public key authentication включена" || warn "SSH: PubkeyAuthentication отключена"
  [[ "$kbd_auth" == "yes" ]] && info "SSH: keyboard-interactive включён; проверь PAM/MFA" || true
  [[ "$x11" == "yes" ]] && warn "SSH: X11Forwarding=yes на почтовом сервере" || pass "SSH: X11 forwarding отключён"
  [[ "$maxtries" =~ ^[0-9]+$ ]] && (( maxtries > 6 )) && warn "SSH: MaxAuthTries=$maxtries" || true
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
  (( VERBOSE == 1 )) && iptables -L -n --line-numbers 2>/dev/null | sed -n '1,120p' || true
  if iptables -S 2>/dev/null | grep -qE '^-A '; then
    pass "Найдены iptables rules"; firewall_active=1
  fi
fi
(( firewall_active == 0 )) && critical "Активный host firewall не обнаружен"

section "BRUTE-FORCE PROTECTION"
bruteforce_protection=0
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
  have cscli && cscli metrics 2>/dev/null | sed -n '1,120p' || true
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
(( ssh_rate > 100 )) && warn "Высокая интенсивность SSH failures: около $ssh_rate событий/сутки" || true

mail_log="$TMPROOT/mail.log"
collect_journal "$mail_log" postfix.service exim4.service exim.service dovecot.service courier-imap.service courier-pop.service
if [[ ! -s "$mail_log" ]]; then
  collect_fallback_logs "$mail_log" '/var/log/mail.log*' '/var/log/maillog*' '/var/log/exim4/mainlog*' '/var/log/exim/mainlog*'
  info "Почтовая статистика получена из файлов логов; точный период может отличаться от $DAYS дней"
fi
info "Анализирую ошибки почтовой авторизации..."
mail_auth_failed="$(grep -Eic 'SASL.*authentication failed|auth failed|authentication failure|Aborted login|LOGIN FAILED|535[ -].*auth|authenticator failed' "$mail_log" 2>/dev/null || true)"
kv "Mail auth failures" "${mail_auth_failed:-0}"
grep -Ei 'SASL.*authentication failed|auth failed|authentication failure|Aborted login|LOGIN FAILED|535[ -].*auth|authenticator failed' "$mail_log" 2>/dev/null | extract_source_ips >"$TMPROOT/mail-top-ips.txt" || true
print_ip_table "$TMPROOT/mail-top-ips.txt" "Top source IPs — mail authentication failures"
mail_rate=$(( ${mail_auth_failed:-0} / (DAYS > 0 ? DAYS : 1) ))
(( mail_rate > 300 )) && warn "Высокая интенсивность mail auth failures: около $mail_rate событий/сутки" || true


section "MAIL FLOW ANALYTICS"
if [[ "$MTA" == "postfix" ]]; then
  # Для корреляции Postfix Queue ID нужны полные строки вида postfix/qmgr и
  # postfix/smtp. journalctl -o cat удаляет этот префикс, поэтому статистика
  # могла показывать нули. Для mail-flow сначала читаем обычные mail.log*,
  # как делал исходный mail_analyzer.sh, и только затем используем journal.
  flow_log="$TMPROOT/mail-flow.log"
  collect_fallback_logs "$flow_log" '/var/log/mail.log*' '/var/log/maillog*'

  if [[ ! -s "$flow_log" ]] && have journalctl; then
    journalctl --since "$DAYS days ago" --no-pager -o short-iso       -u postfix.service >"$flow_log" 2>/dev/null || true
  fi

  if [[ -s "$flow_log" ]]; then
    analyze_postfix_mail_flow "$flow_log" "$TMPROOT"
    incoming_total="$(awk -F= '$1=="incoming"{print $2}' "$TMPROOT/mail-flow-summary.txt" 2>/dev/null || echo 0)"
    outgoing_total="$(awk -F= '$1=="outgoing"{print $2}' "$TMPROOT/mail-flow-summary.txt" 2>/dev/null || echo 0)"
    incoming_unique="$(wc -l <"$TMPROOT/incoming-domains.txt" 2>/dev/null | tr -d ' ' || echo 0)"
    outgoing_unique="$(wc -l <"$TMPROOT/outgoing-domains.txt" 2>/dev/null | tr -d ' ' || echo 0)"

    kv "Incoming delivered" "${incoming_total:-0} message(s), ${incoming_unique:-0} unique sender domain(s)"
    kv "Outgoing delivered" "${outgoing_total:-0} message(s), ${outgoing_unique:-0} unique recipient domain(s)"
    print_domain_table "$TMPROOT/incoming-domains.txt" "Top incoming domains — откуда пришли успешно доставленные письма"
    print_domain_table "$TMPROOT/outgoing-domains.txt" "Top outgoing domains — куда успешно отправлены письма"

    if [[ "${incoming_total:-0}" == 0 && "${outgoing_total:-0}" == 0 ]]; then
      warn "В логах не найдены связанные Postfix qmgr + status=sent события; проверь наличие /var/log/mail.log* и формат логов"
    else
      pass "Mail-flow статистика успешно построена по Postfix Queue ID"
    fi
    info "Статистика построена по доступным Postfix mail.log*; ротационные .gz также учитываются"
  else
    warn "Postfix обнаружен, но mail.log/maillog для анализа трафика не найдены"
  fi
else
  info "Mail flow analytics сейчас поддерживает Postfix; для $MTA раздел пропущен"
fi

section "MTA / RELAY CONFIGURATION"
case "$MTA" in
  postfix)
    if have postconf; then
      postconf myhostname mydomain myorigin mydestination relay_domains mynetworks mynetworks_style \
               smtpd_relay_restrictions smtpd_recipient_restrictions smtpd_sasl_auth_enable \
               smtpd_tls_security_level smtpd_tls_protocols smtpd_tls_mandatory_protocols \
               smtp_tls_security_level 2>/dev/null || true
      relay_restrictions="$(postconf -h smtpd_relay_restrictions 2>/dev/null || true)"
      recipient_restrictions="$(postconf -h smtpd_recipient_restrictions 2>/dev/null || true)"
      mynetworks="$(postconf -h mynetworks 2>/dev/null || true)"
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
if [[ "$IMAP_SERVER" == "dovecot" ]] && have doveconf; then
  doveconf -h ssl_min_protocol 2>/dev/null | sed 's/^/Dovecot ssl_min_protocol: /' || true
  doveconf -h ssl 2>/dev/null | sed 's/^/Dovecot ssl: /' || true
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
    [[ -n "$spf" ]] && { echo "SPF: $spf"; pass "SPF опубликован"; } || warn "SPF для $MAIL_DOMAIN не найден"
    [[ -n "$dmarc" ]] && { echo "DMARC: $dmarc"; pass "DMARC опубликован"; } || warn "DMARC для $MAIL_DOMAIN не найден"
    if [[ -n "$DKIM_SELECTOR" ]]; then
      dkim="$(dig +short TXT "$DKIM_SELECTOR._domainkey.$MAIL_DOMAIN" | tr -d '"' || true)"
      [[ "$dkim" == *"v=DKIM1"* || "$dkim" == *"p="* ]] && { echo "DKIM: $dkim"; pass "DKIM опубликован"; } \
                                                        || warn "DKIM не найден для selector=$DKIM_SELECTOR"
    else
      info "DKIM не проверялся: selector не задан"
    fi
    for ip in $(dig +short A "$MAIL_HOST" 2>/dev/null); do
      ptr="$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//' | head -1)"
      if [[ -n "$ptr" ]]; then
        echo "PTR $ip -> $ptr"
        [[ "$ptr" == "$MAIL_HOST" ]] && pass "PTR совпадает с $MAIL_HOST" || warn "PTR $ip указывает на $ptr, а не $MAIL_HOST"
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
  [[ -n "$empty_passwords" ]] && critical "Аккаунты с пустым password hash: $empty_passwords" || pass "Пустых password hash не найдено"
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

section "FILESYSTEM / INODES"
df -hT -x tmpfs -x devtmpfs 2>/dev/null || df -h 2>/dev/null || true
check_usage_table "Filesystem" < <(df -P -x tmpfs -x devtmpfs 2>/dev/null | tail -n +2)
echo "-- Inodes --"
df -ih -x tmpfs -x devtmpfs 2>/dev/null || true
check_usage_table "Inode" < <(df -Pi -x tmpfs -x devtmpfs 2>/dev/null | tail -n +2)

section "MAIL QUEUE"
case "$MTA" in
  postfix)
    if have postqueue; then
      postqueue -p 2>/dev/null | tail -n 20 || true
      queue_count="$(postqueue -p 2>/dev/null | grep -Ec '^[A-F0-9]+[*!]?[[:space:]]' || true)"
      echo "Approx. queued messages: $queue_count"
      (( queue_count > 1000 )) && critical "Очень большая Postfix queue: $queue_count" \
                                || { (( queue_count > 100 )) && warn "Большая Postfix queue: $queue_count" || pass "Размер Postfix queue не выглядит аварийным"; }
    fi
    ;;
  exim)
    exim_bin="$(command -v exim4 || command -v exim || true)"
    if [[ -n "$exim_bin" ]]; then
      queue_count="$($exim_bin -bpc 2>/dev/null || echo '?')"
      echo "Queued messages: $queue_count"
      [[ "$queue_count" =~ ^[0-9]+$ ]] && (( queue_count > 1000 )) && critical "Очень большая Exim queue: $queue_count" || true
      [[ "$queue_count" =~ ^[0-9]+$ ]] && (( queue_count > 100 && queue_count <= 1000 )) && warn "Большая Exim queue: $queue_count" || true
    fi
    ;;
  sendmail)
    have mailq && mailq 2>/dev/null | tail -n 40 || true
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
  [[ "$selinux_state" == "Enforcing" ]] && pass "SELinux enforcing" || warn "SELinux не в Enforcing"
else
  info "AppArmor/SELinux status tool не найден"
fi

section "CRON / SYSTEMD TIMERS"
echo "-- /etc/cron.d --"
find /etc/cron.d -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | sort || true
echo "-- User crontabs --"
while IFS=: read -r user _ uid _ _ _ shell; do
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

exit "$AUDIT_RC"
