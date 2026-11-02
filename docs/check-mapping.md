# Соответствие проверок 2.3 → 3.0

Строки относятся к `mail-sec-audit.sh` в `main` @ `33f2d51`. Новый ID имеет вид
`SECTION.NAME` или `SECTION.NAME@subject` для проверок, которые повторяются по объектам
(порт, точка монтирования, файл). Модуль правила: `mail_sec_audit/rules/<section>_<name>.py`.

Общие изменения для всех строк:
- нет данных, нет прав, нет утилиты, таймаут или усечение дают **UNKNOWN** с причиной;
- неприменимая проверка даёт **N/A** с причиной;
- у каждого finding есть источник (`cmd:`, `file:`, `log:`, `dns:`, `tls:`), доказательство
  и следующий шаг из каталога ru/en.

## Контекст и обновления

| Строки 2.3 | Было | Новый ID | Изменение |
|---|---|---|---|
| 868–872 | OK root / WARN не root | `CTX.PRIVILEGES` | без изменений |
| 873–877 | OK/WARN FQDN | `CTX.FQDN` | `hostname -f` с timeout |
| 1013, 1015 | OK «MIAB/iRedMail обнаружен» | `CTX.PLATFORM` | INFO: факт определения не является результатом проверки |
| 880–891 | WARN security, WARN любые обновления, OK | `PATCH.PENDING_UPDATES` | WARN только security; прочие обновления INFO. Источник `apt-get -s dist-upgrade` (`-security` в строке `Inst`) вместо `apt list` (R-36) |
| 892–902 | WARN метаданные APT старше 7 дней / INFO | `PATCH.APT_METADATA_AGE` | N/A без APT |
| 903–905 | печать `APT::Periodic` | `PATCH.AUTO_UPDATES` | INFO вместо сырого вывода |
| 906–916 | DNF: WARN/OK | `PATCH.PENDING_UPDATES` | код 100 → обновления, 0 → нет, прочее → UNKNOWN (R-23); логи dnf в приватный каталог |
| 917–926 | YUM: WARN/OK | `PATCH.PENDING_UPDATES` | удалено как отдельная ветка: на EL8+ `yum` это `dnf`, EL7 не поддерживается (Python 3.6) |
| 927–929 | INFO «пакетный менеджер не найден» | `PATCH.PENDING_UPDATES` | UNKNOWN `missing_tool` |
| 931–935 | WARN маркер / OK | `PATCH.REBOOT_REQUIRED` | плюс сравнение запущенного ядра с новейшим в `/boot` (R-35); UNKNOWN, если ни один способ недоступен |

## Стек и службы

| Строки 2.3 | Было | Новый ID | Изменение |
|---|---|---|---|
| 937–967 | определение MTA/IMAP | `STACK.MTA_DETECTED`, `STACK.IMAP_DETECTED` | логика в `facts/mta.py` и `stacks/` |
| 1050 | FAIL «MTA не обнаружен» | `STACK.MTA_DETECTED` | без изменений |
| 1069 | INFO нет IMAP | `STACK.IMAP_DETECTED` | без изменений |
| 974–983 | печать состояния юнитов | evidence `STACK.SERVICE@*` | |
| 985–997 | Mailcow postfix/dovecot контейнер OK/FAIL | `STACK.SERVICE@postfix-mailcow`, `@dovecot-mailcow` | список служб из `stacks/mailcow.py` |
| 998–1011 | Mailcow unhealthy/restarting/exited FAIL/OK | `STACK.CONTAINERS_HEALTH` | N/A вне контейнерного стека |
| 1018–1052 | Postfix/Exim/OpenSMTPD active OK/FAIL, Sendmail OK/WARN | `STACK.SERVICE@<unit>` | UNKNOWN без systemd вместо FAIL |
| 1054–1067 | Dovecot OK/FAIL, Courier OK/WARN | `STACK.SERVICE@<unit>` | то же |
| 450, 457 | версия платформы | `CTX.PLATFORM` | MIAB: `git describe` по каталогу из обёртки (#7); Mailcow: `git describe` по `com.docker.compose.project.working_dir` вместо тега образа (R-44) |

## SSH

| Строки 2.3 | Было | Новый ID | Изменение |
|---|---|---|---|
| 1086–1094 | FAIL root+пароль / WARN / WARN / OK | `SSH.ROOT_LOGIN` | при сбое `sshd -T` UNKNOWN вместо OK (R-04) |
| 1095–1099 | WARN/OK | `SSH.PASSWORD_AUTH` | то же |
| 1100–1104 | OK/WARN | `SSH.PUBKEY_AUTH` | то же |
| 1105–1107 | INFO | `SSH.KBD_INTERACTIVE` | то же |
| 1108–1112 | WARN/OK | `SSH.X11_FORWARDING` | то же |
| 1113–1115 | WARN >6 | `SSH.MAX_AUTH_TRIES` | OK при ≤6 |
| 1116–1118 | WARN «sshd не найден» | все `SSH.*` | N/A, если sshd не установлен; UNKNOWN, если `sshd -T` не сработал |

## Сеть, firewall, brute-force

| Строки 2.3 | Было | Новый ID | Изменение |
|---|---|---|---|
| 1121–1142 | WARN неизвестный listener | `NET.UNEXPECTED_LISTENER@<proto>/<addr>:<port>` | клиентские UDP-сокеты (68, 546) не считаются (R-09); ожидаемые порты стека из `stacks/` (MIAB 12340) |
| 1143 | OK | `NET.LISTENERS` | |
| 1144–1146 | WARN нет `ss` | `NET.LISTENERS` | UNKNOWN |
| 1148–1183 | OK UFW/firewalld/nft/iptables, FAIL нет firewall | `FW.HOST_FIREWALL` | цепочки Docker не считаются (R-06); ошибка чтения или не root → UNKNOWN (R-05); `iptables` только при загруженном `ip_tables` (R-24) |
| 1187–1195 | Mailcow netfilter OK/FAIL | `BRUTE.PROTECTION` | провайдеры защиты задаёт стек |
| 1196–1201 | Fail2ban OK / FAIL не отвечает | `BRUTE.FAIL2BAN` | не root → UNKNOWN (R-29); не установлен → N/A |
| 1202–1220 | WARN нет jail, таблица jail | `BRUTE.FAIL2BAN_JAILS` | INFO со счётчиками |
| 1222 | INFO Fail2ban не установлен | `BRUTE.FAIL2BAN` | N/A |
| 1224–1233 | OK CrowdSec/sshguard, WARN ничего | `BRUTE.PROTECTION` | |

## Авторизация и поток почты

| Строки 2.3 | Было | Новый ID | Изменение |
|---|---|---|---|
| 1236–1322 | счётчики SSH, WARN >100/сутки | `AUTH.SSH_FAILURES` | UNKNOWN без читаемого источника (R-27); фильтрация по периоду для файлов; `sshd-session` (OpenSSH 9.8+) |
| 1240, 1335, 1337 | INFO источник журналов | `completeness.sources` | не finding |
| 1243, 1339 | INFO «Анализирую…» | удалено | сообщения о ходе работы (R-12) |
| 1324–1347 | счётчики почтовой авторизации, WARN >300/сутки | `AUTH.MAIL_FAILURES` | считаются только login-процессы Dovecot и Postfix SASL; `Aborted login` без попыток не считается; IP только из `rip=` или `[ip]` (R-28) |
| 1331 | WARN фильтр периода | `AUTH.*` | UNKNOWN `parse_error` |
| 1350–1395 | статистика Postfix OK/WARN/INFO | `FLOW.STATS` | INFO при наличии данных; UNKNOWN без журналов или при нераспознанном формате; N/A не для Postfix. Новый разбор полей (R-13…R-20, R-43), loopback-переходы не считаются внешней доставкой |
| 1392 | WARN нет python3 | удалено | Python обязателен |

## MTA и relay

| Строки 2.3 | Было | Новый ID | Изменение |
|---|---|---|---|
| 1401–1404 | печать параметров postconf | evidence `MTA.RELAY_RESTRICTIONS` | |
| 1405–1412 | OK/FAIL reject/defer_unauth_destination | `MTA.RELAY_RESTRICTIONS` | эффективные значения для службы порта 25 с учётом `postconf -P` (`smtp/inet`, `smtpd/pass`) и порядка: безусловный `permit` перед reject даёт FAIL (R-25) |
| 1413–1417 | FAIL 0/0 в mynetworks / OK | `MTA.MYNETWORKS` | |
| 1418–1420 | WARN нет postconf | `MTA.*` | UNKNOWN |
| 1422–1432 | Exim FAIL/INFO | `MTA.EXIM_RELAY_HOSTS` | `exim -bP` только с явным списком опций |
| 1434–1436 | OpenSMTPD `smtpctl show config` + INFO | `MTA.OPENSMTPD_RELAY` | подкоманды не существует (R-26); разбор `smtpd.conf`: `match from any … for any` с relay без auth даёт FAIL |
| 1438–1441 | Sendmail `-bv` + INFO | `MTA.SENDMAIL_RELAY` | чтение `sendmail.mc` (#8, R-21) |
| 1443 | INFO «нужна внешняя проверка open relay» | `MTA.EXTERNAL_TEST` | без изменений |

## TLS

| Строки 2.3 | Было | Новый ID | Изменение |
|---|---|---|---|
| 752–755 | WARN handshake | `TLS.HANDSHAKE@<port>` | проба на фактический адрес listener'а (R-39) |
| 757–760 | WARN нет сертификата | `TLS.HANDSHAKE@<port>` | |
| 769–781 | FAIL истёк / FAIL <14 / WARN <30 / OK | `TLS.CERT_EXPIRY@<port>` | UNKNOWN, если дату нельзя разобрать |
| 783–787 | OK/WARN имя | `TLS.CERT_NAME@<port>` | |
| 1456–1458 | WARN нет openssl/ss | `TLS.*` | UNKNOWN |
| 1459–1463 | печать `ssl_min_protocol`, `ssl` | `TLS.DOVECOT_MIN_PROTOCOL` | WARN ниже TLSv1.2 |
| 1465–1475 | `--deep` WARN/OK TLS 1.0 | `TLS.LEGACY_PROTOCOLS@<port>` | TLS 1.0 и 1.1; клиент не может предложить версию → UNKNOWN (R-10); на 25 INFO (оппортунистический TLS) |

## DNS

| Строки 2.3 | Было | Новый ID | Изменение |
|---|---|---|---|
| 1480–1481 | печать MX, A/AAAA | `DNS.MX` | WARN без MX; rcode разбирается (R-37) |
| 1486–1496 | FAIL несколько SPF / OK / WARN нет | `DNS.SPF` | SERVFAIL/таймаут → UNKNOWN; TXT-строки склеиваются без пробела |
| 1497–1508 | DMARC OK/WARN | `DNS.DMARC` | то же |
| 1509–1536 | DKIM OK/WARN/INFO, длина ключа FAIL/WARN/OK | `DNS.DKIM`, `DNS.DKIM_KEY` | пустой `p=` → WARN «ключ отозван» (R-38); без селектора N/A |
| 1537–1548 | MTA-STS, TLS-RPT OK/INFO | `DNS.MTA_STS`, `DNS.TLS_RPT` | |
| 1549–1561 | PTR OK/WARN | `DNS.PTR@<ip>` | |
| 1562–1567 | WARN нет dig / INFO нет домена | `DNS.*` | UNKNOWN / N/A |

## Пользователи, ключи, диск, очередь

| Строки 2.3 | Было | Новый ID | Изменение |
|---|---|---|---|
| 1570–1573 | FAIL/OK UID 0 | `USERS.UID0` | |
| 1575–1576 | печать интерактивных аккаунтов | `USERS.INTERACTIVE_ACCOUNTS` | INFO |
| 1578–1585 | FAIL/OK пустой хеш (чтение `/etc/shadow`) | `USERS.EMPTY_PASSWORD` | `passwd -S`, хеши не читаются (R-41) |
| 1587–1588 | печать NOPASSWD | `USERS.SUDO_NOPASSWD` | INFO |
| 1590–1603 | права authorized_keys OK/WARN, INFO нет файлов | `KEYS.AUTHORIZED_KEYS_PERMS@<path>`, `KEYS.AUTHORIZED_KEYS` | WARN только при записи для группы/других или чужом владельце (R-40); пути из `AuthorizedKeysFile` |
| 1605–1611, 704–718 | FAIL ≥95 / WARN ≥85 / OK, диск и inode | `DISK.USAGE@<mount>`, `DISK.INODES@<mount>` | overlay и squashfs исключены |
| 1613–1623 | путь хранилища почты, INFO | `DISK.MAIL_STORAGE` | путь задаёт стек |
| 1625–1648 | Postfix очередь FAIL/WARN/OK/WARN | `QUEUE.SIZE` | `postqueue -j` (длинные ID, R-08); недоступно → UNKNOWN |
| 1650–1663 | Exim очередь | `QUEUE.SIZE` | нечисловой вывод → UNKNOWN (R-42) |
| 1664–1668 | Sendmail `mailq` печать | `QUEUE.SIZE` | только для настоящего Sendmail, число из `Total requests` |

## Целостность и инвентарь

| Строки 2.3 | Было | Новый ID | Изменение |
|---|---|---|---|
| 1672–1674 | список SUID в стандартных путях | `SUID.STANDARD_PATHS` | INFO с количеством |
| 1675–1681 | FAIL/OK SUID во временных каталогах | `SUID.UNEXPECTED_LOCATIONS` | timeout → UNKNOWN |
| 1682–1687 | `--deep` полный обход | `SUID.FULL_SCAN` | INFO; `/var/lib/docker` исключён |
| 1689–1696 | WARN/OK world-writable | `PERMS.WORLD_WRITABLE` | каталоги со sticky-битом отдельно (INFO) (R-45) |
| 1699–1707 | WARN/OK failed units | `MAC.FAILED_UNITS` | |
| 1708–1720 | AppArmor печать, SELinux OK/WARN, INFO нет | `MAC.FRAMEWORK` | состояние из `/sys` без запуска утилит |
| 1722–1744 | cron, timers, юниты печать | `SCHED.INVENTORY` | INFO; crontab читается из spool, а не через `crontab -u` |
| 1746–1765 | backup INFO/WARN | `BACKUP.INDICATORS` | |
| 1767–1770 | `last`, `lastb` печать | `LOGIN.RECENT` | INFO с выдержкой |
| 1772–1782 | `--deep` debsums / rpm -Va INFO | `PKG.INTEGRITY` | debsums с изменёнными файлами → WARN; rpm с `--noscripts` (#8) |
| 1784–1787 | `--deep` недавно изменённые | `RECENT.MODIFIED` | INFO |

## Интерактивный режим

| Строки 2.3 | Было | Новое | Изменение |
|---|---|---|---|
| 652–702 | меню Fail2ban, ban/unban с подтверждением `BAN`/`UNBAN` | `mail_sec_audit/interactive.py` | сохраняется. Защита от self-lockout: все IP с установленной SSH-сессией (`ss`), `SSH_CONNECTION`/`SSH_CLIENT`, собственные адреса, не глобальные адреса (R-30). Работает и с `--report` (R-31). Результаты действий выводятся в терминал и в syslog (`logger`), в findings не попадают |
| 1805 | INFO «Управление блокировками не запускалось» | удалено | шум (R-12) |
