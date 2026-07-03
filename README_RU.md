# Mail Security Audit

<p align="center">
  <strong>Read-only аудит безопасности и рабочего состояния почтовых серверов Linux.</strong>
</p>

<p align="center">
  Postfix · Exim · Dovecot · Fail2ban · UFW · nftables · TLS · DNS · Почтовые логи
</p>

<p align="center">
  <a href="https://github.com/Anton-Babaskin/mail-sec-audit/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/Anton-Babaskin/mail-sec-audit/ci.yml?branch=main&label=CI" alt="CI">
  </a>
  <img src="https://img.shields.io/badge/Bash-5%2B-4EAA25?logo=gnubash&logoColor=white" alt="Bash 5+">
  <img src="https://img.shields.io/badge/Linux-Debian%20%7C%20Ubuntu-FCC624?logo=linux&logoColor=black" alt="Debian и Ubuntu">
  <img src="https://img.shields.io/badge/Mode-read--only%20by%20default-2ea44f" alt="Read-only by default">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="MIT License">
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README_RU.md">Русский</a>
</p>

---

## Обзор

**Mail Security Audit** — single-file Bash-инструмент для проверки безопасности и рабочего состояния Linux-почтовых серверов. Он определяет установленный почтовый стек, проверяет SSH и сетевую доступность, анализирует ошибки авторизации, проверяет TLS и DNS, смотрит почтовые очереди и собирает понятный терминальный отчёт.

Режим по умолчанию безопасен для диагностики production-серверов: скрипт читает состояние системы и показывает findings. Он не меняет firewall, не перезапускает сервисы, не устанавливает пакеты, не редактирует конфигурацию почтового сервера и не блокирует IP автоматически.

## Что Проверяется

| Область | Покрытие |
|---|---|
| Состояние системы | ОС, ядро, обновления, необходимость перезагрузки, failed services, диск и inode |
| SSH | Эффективная конфигурация `sshd`, root login, password auth, ключи, успешные и неудачные входы |
| Сеть | Слушающие порты, публичные сервисы, неожиданные порты, опасные DB-порты наружу |
| Firewall | UFW, nftables, iptables policies, Fail2ban chains |
| Brute-force защита | Fail2ban jails и counters, CrowdSec и sshguard, безопасное ручное меню блокировок |
| Почтовый стек | Определение Postfix, Exim, Sendmail, OpenSMTPD, Dovecot, Courier |
| Mail auth | Ошибки Dovecot и Postfix SASL, топ атакующих IPv4 и IPv6 |
| Mail flow | Статистика Postfix по доменам отправителей и получателей, delivery stats, Queue ID correlation |
| Очереди | Размер очередей Postfix и Exim, deferred mail, warning thresholds |
| Relay safety | Postfix relay restrictions, `mynetworks`, `reject_unauth_destination`, подсказки по Exim |
| TLS | HTTPS, SMTP, IMAP, POP3 STARTTLS, subject, issuer, expiry, legacy TLS в deep mode |
| DNS | MX, SPF, DMARC, DKIM selector, PTR, проверка mail hostname |
| Integrity | SUID/SGID, world-writable files, package integrity, cron, timers, backup tooling |

## Быстрый Старт

Склонируй репозиторий и запусти скрипт на почтовом сервере:

```bash
git clone https://github.com/Anton-Babaskin/mail-sec-audit.git
cd mail-sec-audit
chmod 700 mail-sec-audit.sh
sudo ./mail-sec-audit.sh
```

Запуск проверки с доменом и hostname:

```bash
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com \
  --dkim-selector default
```

Сохранение локального отчёта:

```bash
sudo ./mail-sec-audit.sh \
  --hostname mail.example.com \
  --domain example.com \
  --report ./reports/mail-audit-$(date +%F).log
```

Отчёты могут содержать чувствительные operational данные. Директория `reports/` исключена из git.

## Параметры

| Параметр | Описание |
|---|---|
| `--days N` | Анализировать логи за последние `N` дней. По умолчанию: `7` |
| `--hostname HOST` | FQDN почтового сервера для TLS-проверок |
| `--domain DOMAIN` | Основной почтовый домен для DNS-проверок |
| `--dkim-selector NAME` | DKIM selector для DNS lookup |
| `--mail-top N` | Количество доменов отправителей и получателей. По умолчанию: `20` |
| `--verbose` | Расширенный диагностический вывод |
| `--interactive` | Открыть ручное меню управления Fail2ban |
| `--deep` | Запустить более медленные и детальные проверки |
| `--report FILE` | Сохранить вывод аудита в файл |
| `--no-color` | Отключить ANSI-цвета |
| `-h`, `--help` | Показать справку |

## Коды Завершения

| Код | Значение |
|---:|---|
| `0` | Аудит завершён без предупреждений и критических findings |
| `1` | Найдены предупреждения |
| `2` | Найдены критические findings |

## Модель Безопасности

В обычном режиме аудита скрипт не:

- изменяет firewall rules;
- перезапускает сервисы;
- устанавливает пакеты;
- меняет SSH, Postfix, Exim, Dovecot или DNS configuration;
- удаляет письма из очереди;
- блокирует или разблокирует IP автоматически.

Единственный workflow с возможностью записи — явно включённое интерактивное меню Fail2ban. Каждое действие требует подтверждения, а IP текущей SSH-сессии защищён от случайной блокировки.

Подробнее: [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## Требования

Рекомендуемое окружение:

- Debian или Ubuntu;
- Bash 5 или новее;
- root privileges для полного покрытия проверок.

Дополнительные утилиты расширяют покрытие, если доступны:

```text
openssl
dig
sqlite3
fail2ban-client
journalctl
ss
nft
iptables
postconf
postqueue
doveconf
```

Недоступные проверки пропускаются без остановки аудита.

## Структура Проекта

```text
.
├── mail-sec-audit.sh          # Основной audit script
├── README.md                  # Документация на английском
├── README_RU.md               # Документация на русском
├── docs/                      # Подробные гайды и проектные заметки
├── examples/                  # Примеры окружения
├── tests/                     # Smoke tests
├── .github/                   # CI, issue templates, PR template
├── CONTRIBUTING.md            # Правила contribution
├── SECURITY.md                # Security policy
├── CHANGELOG.md               # Release notes
└── LICENSE                    # MIT License
```

## Документация

- [Usage guide](docs/USAGE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Development guide](docs/DEVELOPMENT.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Разработка

Перед pull request запусти локальные проверки:

```bash
bash -n mail-sec-audit.sh
bash tests/smoke.sh
shellcheck mail-sec-audit.sh tests/*.sh
```

GitHub Actions запускает тот же базовый набор проверок на push и pull request.

## Roadmap

Планируемые companion tools:

- `mail-external-audit`: внешние проверки relay, TLS, banner, DNS, RBL и портов с другого хоста;
- `mail-audit-collector`: централизованный сбор, сравнение baseline, JSON output, fleet reporting и notifications.

## Важные Замечания

- Локальный анализ конфигурации не заменяет внешний open-relay test.
- Количество failed logins не всегда равно количеству уникальных атакующих.
- Fail2ban counters могут включать адреса, которые уже были разблокированы.
- Mail-flow analytics сейчас наиболее детально работает для Postfix.
- Перед ручной блокировкой IP всегда проверяй адрес.

## Лицензия

Проект распространяется по [MIT License](LICENSE).

## Автор

**Anton Babaskin**  
GitHub: [@Anton-Babaskin](https://github.com/Anton-Babaskin)

