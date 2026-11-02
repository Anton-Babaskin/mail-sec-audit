# Mail Security Audit

<p align="center">
  <strong>Аудит безопасности и состояния Linux-почтового сервера одной командой. Только чтение.</strong>
</p>

<p align="center">
  <a href="https://github.com/Anton-Babaskin/mail-sec-audit/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/Anton-Babaskin/mail-sec-audit/ci.yml?branch=main&label=CI" alt="CI">
  </a>
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776ab?logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/Mode-read--only%20by%20default-2ea44f" alt="Read-only">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="MIT">
</p>

<p align="center"><a href="README.md">English</a> · <a href="README_RU.md">Русский</a></p>

---

## Быстрый старт

```bash
git clone https://github.com/Anton-Babaskin/mail-sec-audit.git
cd mail-sec-audit
sudo bash mail-sec-audit.sh
```

Скрипт запускает пакет `mail_sec_audit`, лежащий рядом, системным Python 3.9+
в изолированном режиме. Ничего не устанавливается и не скачивается. Есть сборка
одним файлом:

```bash
python3 tools/build_zipapp.py          # создаёт dist/mail-sec-audit.pyz
sudo python3 -I dist/mail-sec-audit.pyz --domain example.org
```

## Платформы

| Платформа | Как проверяется |
|---|---|
| Mail-in-a-Box | Postfix/Dovecot на хосте, `/var/log/mail.log` в обоих форматах строк, версия через `git describe` в каталоге установки. **Команда `mailinabox` не запускается никогда**: она стартует setup. |
| Mailcow | Docker: `docker ps/inspect/logs`, `postconf`, `doveconf`, `postqueue` через `docker exec`; postscreen на 25; контейнер netfilter как защита от перебора. `mailcow.conf` и `update.sh` не трогаются. |
| iRedMail | Postfix/Dovecot на хосте, журналы Dovecot в `/var/log/dovecot/`, переходы через amavis распознаются. |
| Generic Postfix | Файлы журналов или journald (включая `postfix@-.service`). |
| Exim, OpenSMTPD, Sendmail | Определение, состояние службы, эвристика relay и размер очереди. Статистика почты только для Postfix. |

Дистрибутивы: Debian 11+, Ubuntu 22.04+, RHEL/Rocky/Alma 9 (системный Python 3.9+).
Для RHEL 8 нужен пакет `python39`; CentOS/RHEL 7 не поддерживаются.

## Что проверяется

- **Обновления и перезагрузка**: ожидающие security-обновления (APT/DNF), возраст
  списков APT, автообновления, маркер перезагрузки и сравнение ядра.
- **Почтовая платформа**: MTA и IMAP, обязательные службы и контейнеры, их здоровье.
- **SSH**: эффективные значения `sshd -T`, права и владельцы authorized_keys.
- **Доступность снаружи**: listener'ы не на loopback вне ожидаемых портов; host
  firewall с реальным запретом по умолчанию (цепочки Docker не считаются);
  Fail2ban/CrowdSec/sshguard/защита стека.
- **Авторизация**: ошибки SSH и почтовой авторизации, топ адресов.
- **Поток почты (Postfix)**: письма, доставки, попытки, bounce/deferred, топы
  пользователей, отправителей и доменов. Переходы через контент-фильтр не
  удваивают счёт, враждебные поля журнала не подделывают результат.
- **Relay**: ограничения Postfix для порта 25 с учётом `master.cf` и порядка
  правил, mynetworks; relay в Exim, OpenSMTPD, Sendmail.
- **TLS**: локальное рукопожатие, срок и имя сертификата, минимальный протокол
  Dovecot; с `--deep` приём TLS 1.0/1.1.
- **DNS** (с `--domain`): MX, SPF, DMARC, DKIM и длина ключа, MTA-STS, TLS-RPT,
  PTR с учётом кода ответа (SERVFAIL не означает «записи нет»).
- **Гигиена хоста**: UID 0, аккаунты без пароля (`passwd -S`, хеши не читаются),
  sudo NOPASSWD, диск и inode, SUID, пути с записью для всех, отказавшие юниты,
  AppArmor/SELinux, cron и таймеры, признаки бэкапов, входы; с `--deep`
  целостность пакетов и недавно изменённые файлы.

Полный список со стабильными ID: [docs/check-mapping.md](docs/check-mapping.md).

## Результаты и коды возврата

У каждого finding есть стабильный ID (`SSH.ROOT_LOGIN`, `TLS.CERT_EXPIRY@465`),
статус, источник, доказательство и следующий шаг.

| Статус | Значение |
|---|---|
| `OK` | проверено, всё в порядке |
| `INFO` | инвентарь или контекст, действий не требуется |
| `WARN` | нужно посмотреть |
| `FAIL` | критично |
| `UNKNOWN` | проверить не удалось: нет прав, нет утилиты, таймаут, усечение или нечитаемые данные. Причина указана. Никогда не считается за OK. |
| `N/A` | неприменимо на этом хосте или не запрошено (например, DNS без `--domain`) |

| Код | Значение |
|---:|---|
| `0` | нет WARN, FAIL и UNKNOWN |
| `1` | есть WARN или UNKNOWN, FAIL нет |
| `2` | есть FAIL |
| `64` | ошибка аргументов |
| `69` | нет Python 3.9+ |
| `73` | файл отчёта нельзя безопасно создать или дописать |
| `75` | уже идёт другой аудит |
| `128+N` | остановлено сигналом N (130 для Ctrl+C) |

## Примеры

```bash
# период, имя и DNS
sudo bash mail-sec-audit.sh --from 2026-08-01 --to 2026-08-07 \
  --hostname mail.example.com --domain example.com --dkim-selector mail

# машиночитаемый отчёт (HealthResult FleetOps), с маскированием, в новый приватный файл
sudo bash mail-sec-audit.sh --format json --redact --report /root/audit.json

# JSON в формате 2.3 для существующих потребителей
sudo bash mail-sec-audit.sh --format json-v1 --report /root/audit-v1.json

# медленные проверки, вывод на русском
sudo bash mail-sec-audit.sh --deep --lang ru

# порты мониторинга как ожидаемые публичные listener'ы
sudo MAIL_AUDIT_ALLOWED_PORTS="10050 9100" bash mail-sec-audit.sh
```

Язык: `--lang ru|en`, без флага берётся из `LC_ALL`, `LC_MESSAGES`, `LANG`.
Примеры отчётов из синтетического тестового сценария лежат в [examples/](examples/).
Все опции: `bash mail-sec-audit.sh --help`, подробнее: [docs/USAGE.md](docs/USAGE.md).

## JSON

`--format json` выдаёт документ FleetOps `HealthResult`: `schema_version`
(`"1.0"`), `host{id, hostname}`, `collected_at`, `duration_ms`, `overall_status`
(`ok`/`warning`/`critical`/`unknown`) и `checks[]` с полями `name`, `status`,
`summary`, `metrics`, `reason`, `error`, `timed_out`, `duration_ms`, `raw_ref`.
Исходный статус, секция, источник, доказательство и следующий шаг лежат в
`metrics`. Версия, период и пробы находятся в проверке `CTX.AUDIT`, статистика
Postfix в `FLOW.STATISTICS`, файловые системы в `DISK.FILESYSTEMS`. `host.id` —
хеш от `/etc/machine-id`; сам machine-id не публикуется.

`--format json-v1` сохраняет документ 2.3 (`schema_version: 1`) с прежними
именами полей и дополнительными новыми.

## Модель безопасности

- Аудит только читает систему. Единственный изменяющий режим — `--interactive`
  (ban/unban в Fail2ban, каждое действие подтверждается вводом `BAN`/`UNBAN`).
  Отказ для адресов самого хоста, всех открытых SSH-сессий и неглобальных адресов.
- Все внешние команды идут через один runner с таблицей разрешённых аргументов,
  таймаутом и лимитом вывода, без shell. `mailinabox` и `update.sh` запрещены с
  любыми аргументами; для `docker` разрешены только `ps`, `inspect`, `logs` и
  `exec` без опций, внутренняя команда проверяется по той же таблице.
- Секреты не читаются: хеши паролей, private keys, `sasl_passwd`, `mailcow.conf`,
  тела писем. `doveconf` не вызывается с `-x`.
- Сеть: TLS-пробы только к локальным адресам listener'ов, DNS только с `--domain`.
  Всё перечисляется в отчёте.
- Отчёт создаётся через `O_EXCL|O_NOFOLLOW` с правами 0600; существующие файлы и
  symlink отклоняются. Временные файлы — в приватном каталоге, который удаляется
  при выходе и по сигналу.

Подробнее: [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## Связанные проекты

- [miab-radar](https://github.com/Anton-Babaskin/miab-radar): диагностика доставки для Mail-in-a-Box (разбор отдельных писем, DNSBL).
- [smtp-egress-audit](https://github.com/Anton-Babaskin/smtp-egress-audit): атрибуция исходящих SMTP-соединений.
- [FleetOps](https://github.com/Anton-Babaskin/FleetOps): принимает HealthResult из `--format json`.

## Лицензия

MIT, см. [LICENSE](LICENSE).
