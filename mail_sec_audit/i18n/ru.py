"""Русский каталог. Ключи и плейсхолдеры совпадают с ``en.py``."""

from __future__ import annotations

MESSAGES: dict[str, str] = {
    # --- командная строка -----------------------------------------------------
    "cli.usage": (
        "Использование:\n"
        "  sudo bash mail-sec-audit.sh [опции]\n"
        "\n"
        "Опции:\n"
        "  --days N              Период анализа журналов в днях, по умолчанию 7\n"
        "  --mail-top N          Строк в таблицах почтовой статистики, по умолчанию 20\n"
        "  --from YYYY-MM-DD     Первый день периода, включительно\n"
        "  --to YYYY-MM-DD       Последний день периода, включительно\n"
        "  --hostname FQDN       Имя почтового сервера для TLS-проверок\n"
        "  --domain DOMAIN       Почтовый домен для MX/SPF/DMARC (включает DNS-запросы)\n"
        "  --dkim-selector SEL   DKIM-селектор для DNS-проверки\n"
        "  --platform NAME       auto, generic, mailcow, iredmail или mailinabox\n"
        "  --format FORMAT       text, json или fleetops\n"
        "  --lang LANG           ru или en; по умолчанию из LC_ALL, LC_MESSAGES, LANG\n"
        "  --redact              Скрыть e-mail, IP-адреса, имена хоста и пользователей\n"
        "  --deep                Медленные проверки: старые версии TLS, целостность пакетов, полный поиск SUID\n"
        "  --report FILE         Записать отчёт в новый файл с правами 0600\n"
        "  --append-report FILE  Дописать текстовый отчёт в существующий приватный файл\n"
        "  --interactive         После аудита открыть меню Fail2ban (изменения с подтверждением)\n"
        "  --verbose             Показывать доказательства для каждого finding\n"
        "  --no-color            Отключить ANSI-цвета\n"
        "  --version             Показать версию и выйти\n"
        "  -h, --help            Показать справку\n"
        "\n"
        "Дополнительные разрешённые публичные порты:\n"
        '  MAIL_AUDIT_ALLOWED_PORTS="10050 9100" sudo bash mail-sec-audit.sh\n'
        "\n"
        "Аудит только читает систему. Изменения возможны только в режиме --interactive\n"
        "и только после подтверждения каждой операции.\n"
        "\n"
        "Коды возврата: 0 чисто, 1 WARN или UNKNOWN, 2 FAIL, 64 ошибка аргументов, 69 нет\n"
        "подходящего Python, 73 ошибка файла отчёта, 75 уже идёт другой аудит, 128+N сигнал N."
    ),
    "cli.error.prefix": "Ошибка: {message}",
    "cli.error.requires_value": "{option} требует значение",
    "cli.error.days": "--days требует число от 1 до 3650",
    "cli.error.mail_top": "--mail-top требует число от 1 до 100",
    "cli.error.date": "{option} требует корректную дату YYYY-MM-DD",
    "cli.error.dns_name": "{option} содержит недопустимое имя: {value}",
    "cli.error.platform": "неизвестная платформа: {value}",
    "cli.error.format": "--format поддерживает text, json или fleetops",
    "cli.error.lang": "--lang поддерживает ru или en",
    "cli.error.report_once": "--report и --append-report можно указать только один раз",
    "cli.error.json_append": "--append-report нельзя сочетать с JSON; используй отдельный файл",
    "cli.error.json_interactive": "--interactive нельзя сочетать с JSON",
    "cli.error.period": "--from не может быть позже --to",
    "cli.error.ports": "MAIL_AUDIT_ALLOWED_PORTS содержит недопустимый порт: {value}",
    "cli.error.unknown_option": "неизвестная опция: {option}",
    "cli.error.report": "{message}",
    "cli.error.lock": "другой запуск mail-sec-audit держит {path}; повтори позже",
    "report.error.parent": "не удалось создать каталог отчёта: {path}",
    "report.error.symlink": "отказ: путь отчёта является символической ссылкой: {path}",
    "report.error.exists": "файл уже существует; используй --append-report: {path}",
    "report.error.create": "не удалось безопасно создать отчёт: {path} ({detail})",
    "report.error.append_missing": "для --append-report нужен существующий обычный файл: {path}",
    "report.error.append_unsafe": "отказ дописывать: {path} ({detail})",
    "report.error.write": "не удалось записать отчёт: {path} ({detail})",
    "signal.stopped": "Остановлено сигналом {signal}; временные файлы удалены.",
    # --- терминал -------------------------------------------------------------
    "ui.title": "АУДИТ БЕЗОПАСНОСТИ ПОЧТОВОГО СЕРВЕРА",
    "ui.banner.host": "хост",
    "ui.banner.period": "период",
    "ui.status.OK": "  OK  ",
    "ui.status.INFO": " INFO ",
    "ui.status.WARN": " WARN ",
    "ui.status.FAIL": " FAIL ",
    "ui.status.UNKNOWN": " UNKN ",
    "ui.status.N/A": " N/A  ",
    "ui.evidence": "источник",
    "ui.next": "шаг",
    "ui.reason": "причина",
    "ui.summary": "Итог",
    "ui.result.critical": "ИТОГ: КРИТИЧНО - сначала исправь FAIL, затем WARN",
    "ui.result.review": "ИТОГ: НУЖНА ПРОВЕРКА - критических проблем нет",
    "ui.result.unknown": "ИТОГ: НЕПОЛНЫЙ - часть проверок вернула UNKNOWN, проверь их вручную",
    "ui.result.clean": "ИТОГ: ЧИСТО - явных проблем не найдено",
    "ui.completeness": "Источники данных",
    "ui.completeness.none": "все запрошенные источники прочитаны",
    "ui.probes.local": "Локальные пробы",
    "ui.probes.external": "Внешние запросы",
    "ui.probes.none": "нет",
    "ui.no_data": "нет данных",
    "ui.ctx.date": "Дата",
    "ui.ctx.host": "Хост",
    "ui.ctx.mail_host": "FQDN / имя для TLS",
    "ui.ctx.domain": "Почтовый домен",
    "ui.ctx.domain_none": "(не указан)",
    "ui.ctx.platform": "Платформа",
    "ui.ctx.period": "Период анализа",
    "ui.ctx.kernel": "Ядро",
    "ui.ctx.os": "ОС",
    "ui.ctx.mta": "MTA",
    "ui.ctx.imap": "IMAP/POP3",
    "ui.ctx.lang": "Язык",
    "ui.table.rank": "#",
    "ui.table.events": "СОБЫТИЯ",
    "ui.table.source_ip": "IP ИСТОЧНИКА",
    "ui.table.mailbox": "ЯЩИК / ОТПРАВИТЕЛЬ",
    "ui.table.submitted": "ПРИНЯТО",
    "ui.table.delivered": "ДОСТАВЛЕНО",
    "ui.table.recipients": "ПОЛУЧАТЕЛИ",
    "ui.table.bytes": "БАЙТЫ",
    "ui.table.domain": "ДОМЕН",
    "ui.table.count": "КОЛ-ВО",
    "source.state.ok": "прочитан",
    "source.state.missing": "отсутствует",
    "source.state.denied": "нет прав",
    "source.state.timeout": "превышено время",
    "source.state.truncated": "обрезан по лимиту размера",
    "source.state.error": "ошибка",
    "source.state.empty": "пуст",
    # --- секции -----------------------------------------------------------------
    "section.CTX": "КОНТЕКСТ АУДИТА",
    "section.PATCH": "ОБНОВЛЕНИЯ / ПЕРЕЗАГРУЗКА",
    "section.STACK": "ПОЧТОВАЯ ПЛАТФОРМА / СЛУЖБЫ",
    "section.SSH": "ЭФФЕКТИВНАЯ КОНФИГУРАЦИЯ SSHD",
    "section.NET": "СЛУШАЮЩИЕ ПОРТЫ / ПУБЛИЧНЫЕ АДРЕСА",
    "section.FW": "FIREWALL",
    "section.BRUTE": "ЗАЩИТА ОТ ПЕРЕБОРА",
    "section.AUTH": "СОБЫТИЯ АВТОРИЗАЦИИ",
    "section.FLOW": "ПОТОК ПОЧТЫ",
    "section.MTA": "MTA / RELAY",
    "section.TLS": "TLS",
    "section.DNS": "DNS / ЗАПИСИ АУТЕНТИФИКАЦИИ ПОЧТЫ",
    "section.USERS": "ЛОКАЛЬНЫЕ ПОЛЬЗОВАТЕЛИ / ПРИВИЛЕГИИ",
    "section.KEYS": "SSH AUTHORIZED_KEYS",
    "section.DISK": "ДИСК / ФАЙЛОВЫЕ СИСТЕМЫ",
    "section.QUEUE": "ПОЧТОВАЯ ОЧЕРЕДЬ",
    "section.SUID": "SUID / SGID",
    "section.PERMS": "ПУТИ С ЗАПИСЬЮ ДЛЯ ВСЕХ",
    "section.MAC": "ОТКАЗАВШИЕ СЛУЖБЫ / MAC",
    "section.SCHED": "CRON / ТАЙМЕРЫ SYSTEMD",
    "section.BACKUP": "РЕЗЕРВНОЕ КОПИРОВАНИЕ",
    "section.LOGIN": "ПОСЛЕДНИЕ ВХОДЫ",
    "section.PKG": "ЦЕЛОСТНОСТЬ ПАКЕТОВ",
    "section.RECENT": "НЕДАВНО ИЗМЕНЁННЫЕ ФАЙЛЫ",
    "section.SUMMARY": "ИТОГ",
    # --- общие UNKNOWN / N/A ------------------------------------------------------
    "common.unknown.missing_tool": "Не проверено: {tool} не установлен",
    "common.unknown.permission_denied": "Не проверено: нет прав на чтение {source}",
    "common.unknown.timeout": "Не проверено: {source} не завершился вовремя",
    "common.unknown.truncated": "Неполные данные: {source} превысил лимит вывода",
    "common.unknown.no_data": "Нет данных: {source} не вернул пригодных данных",
    "common.unknown.command_failed": "Не проверено: {source} завершился с ошибкой ({detail})",
    "common.unknown.parse_error": "Не проверено: вывод {source} не распознан",
    "common.unknown.internal_error": "Внутренняя ошибка проверки ({detail}); остальной отчёт не затронут",
    "common.na.not_applicable": "Неприменимо: {detail}",
    "common.na.not_requested": "Не запрошено: {detail}",
    "common.next.unknown": "Запусти аудит от root или установи недостающую утилиту и повтори проверку.",
    "common.next.internal_error": "Сообщи об ошибке, приложив JSON-отчёт; проверь этот пункт вручную.",
    # --- CTX ----------------------------------------------------------------------
    "ctx.privileges.ok": "Запущено от root: доступны все локальные проверки",
    "ctx.privileges.warn": "Запущено не от root: проверки, которым нужен root, вернут UNKNOWN",
    "ctx.privileges.next": "Запусти аудит через sudo, чтобы получить полный результат.",
    "ctx.fqdn.ok": "Имя хоста {name} выглядит как FQDN",
    "ctx.fqdn.warn": "Имя хоста {name} не выглядит как FQDN",
    "ctx.fqdn.next": "Задай почтовому хосту полное имя, совпадающее с PTR и сертификатом.",
    "ctx.platform.info": "Платформа: {platform} {version}",
    "interactive.no_tty": "Интерактивное меню пропущено: stdin или stdout не терминал",
    "interactive.need_root": "Для управления Fail2ban нужен root",
    "interactive.unavailable": "Fail2ban не отвечает; меню не открыто",
    "interactive.title": "ДЕЙСТВИЯ FAIL2BAN - изменения только после подтверждения",
    "interactive.menu.ban": "  1) Заблокировать один адрес в выбранном jail",
    "interactive.menu.unban": "  2) Разблокировать адрес во всех jail",
    "interactive.menu.show": "  3) Показать текущие блокировки",
    "interactive.menu.exit": "  0) Выйти без изменений",
    "interactive.prompt.action": "Действие: ",
    "interactive.prompt.choice": "Выбор [0=отмена]: ",
    "interactive.prompt.jail": "Номер jail [0=отмена]: ",
    "interactive.prompt.unban": "Адрес для разблокировки: ",
    "interactive.candidates": "Кандидаты из этого отчёта:",
    "interactive.manual": "   m) ввести адрес вручную",
    "interactive.unknown_choice": "Неизвестный пункт меню",
    "interactive.cancelled": "Операция отменена",
    "interactive.no_jails": "Fail2ban не сообщил ни одного jail",
    "interactive.will_run": "Будет выполнено: {command}",
    "interactive.confirm": "Для подтверждения введи {word}: ",
    "interactive.banned": "{ip} заблокирован в jail {jail}",
    "interactive.failed": "Fail2ban не смог заблокировать {ip} в jail {jail}",
    "interactive.unbanned": "Команда разблокировки {ip} отправлена в Fail2ban",
    "interactive.none_banned": "Заблокированных адресов нет",
    "interactive.refuse.invalid": "Некорректный IP-адрес: {ip}",
    "interactive.refuse.not_global": "Отказ: {ip} не является глобально маршрутизируемым адресом",
    "interactive.refuse.protected": "Отказ: {ip} принадлежит этому хосту или открытой SSH-сессии",
    "auth.table.ssh_failed": "Топ адресов - ошибки SSH",
    "auth.table.ssh_accepted": "Топ адресов - успешные входы SSH",
    "auth.table.mail_failed": "Топ адресов - ошибки почтовой авторизации",
    "flow.kv.observed": "Период в журналах",
    "flow.kv.lines": "Строки журнала",
    "flow.kv.lines_value": "{period} в периоде / {scanned} просмотрено",
    "flow.total.outbound_messages": "Исходящих писем",
    "flow.total.outbound_deliveries": "Исходящих доставок",
    "flow.total.authenticated_submissions": "Аутентифицированных отправок",
    "flow.total.authenticated_outbound_messages": "Аутентиф., доставлено наружу",
    "flow.total.incoming_messages": "Писем доставлено локально",
    "flow.total.incoming_deliveries": "Локальных доставок",
    "flow.total.bounced_deliveries": "Попыток с bounce",
    "flow.total.deferred_deliveries": "Отложенных попыток",
    "flow.total.internal_hops": "Переходов через фильтр (не считаются)",
    "flow.total.outbound_bytes": "Исходящих байт (размер в очереди)",
    "flow.table.users": "Топ аутентифицированных SMTP-пользователей",
    "flow.table.senders": "Топ envelope-отправителей (доставлено наружу)",
    "flow.table.sender_domains": "Топ доменов отправителей (письма наружу)",
    "flow.table.recipient_domains": "Топ доменов получателей (внешние доставки)",
    "flow.table.incoming_domains": "Топ доменов отправителей локально доставленной почты",
}
