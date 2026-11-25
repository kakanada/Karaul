#!/usr/bin/env python3
"""Karaul watches SSH logins on one server: log every login, notify Telegram outside the whitelist."""

import fcntl
import html
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import syslog
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

CONFIG = Path("/etc/karaul/config.json")
WHITELIST = Path("/etc/karaul/whitelist.txt")
LOG = Path("/var/log/karaul/access.log")
OFFSET = Path("/var/lib/karaul/offset")
PENDING = Path("/var/lib/karaul/pending")
MAX_BYTES = 128 * 1024 * 1024
KEEP_BYTES = 32 * 1024 * 1024
TZ = ZoneInfo("Europe/Moscow")
PAGE_SIZE = 5

KEYBOARD = {
    "keyboard": [
        [{"text": "Белый список"}, {"text": "Последние входы"}],
        [{"text": "Добавить IP"}, {"text": "Удалить IP"}],
        [{"text": "Статус"}, {"text": "Помощь"}],
    ],
    "resize_keyboard": True,
    "is_persistent": True,
}

BUTTONS = {
    "Белый список": "/list",
    "Последние входы": "/log",
    "Добавить IP": "/add",
    "Удалить IP": "/del",
    "Статус": "/status",
    "Помощь": "/help",
}

COMMANDS = [
    {"command": "status", "description": "Состояние сервера"},
    {"command": "list", "description": "Белый список"},
    {"command": "log", "description": "Последние входы"},
    {"command": "add", "description": "Добавить IP"},
    {"command": "del", "description": "Удалить IP"},
    {"command": "comment", "description": "Комментарий к IP"},
    {"command": "help", "description": "Помощь"},
]


def load_config():
    with CONFIG.open(encoding="utf-8") as fh:
        return json.load(fh)


def owner_id(cfg=None):
    cfg = cfg or load_config()
    if cfg.get("owner_id") not in (None, ""):
        return int(cfg["owner_id"])
    return int(cfg["chat_id"])


def from_owner(owner, chat, user):
    if not chat or chat.get("type") not in (None, "private"):
        return False
    if chat.get("id") != owner:
        return False
    if user and user.get("id") != owner:
        return False
    return True


def server_name():
    return load_config().get("server") or os.uname().nodename


def now_str():
    return datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S МСК")


def canon_ip(value):
    return str(ipaddress.ip_address(value.strip()))


def parse_whitelist_text(text):
    rows = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        head, _, comment = raw.partition(" ")
        try:
            ip = canon_ip(head)
        except ValueError:
            continue
        rows.append({"ip": ip, "comment": comment.strip()[:80]})
    return rows


def format_whitelist(rows):
    lines = []
    for row in rows:
        if row.get("comment"):
            lines.append("%s %s" % (row["ip"], row["comment"]))
        else:
            lines.append(row["ip"])
    return ("\n".join(lines) + "\n") if lines else ""


def read_entries():
    if not WHITELIST.exists():
        return []
    with WHITELIST.open(encoding="utf-8") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
        return parse_whitelist_text(fh.read())


def write_entries(rows):
    WHITELIST.parent.mkdir(parents=True, exist_ok=True)
    with WHITELIST.open("a+", encoding="utf-8") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        fh.seek(0)
        fh.truncate()
        fh.write(format_whitelist(rows))
        fh.flush()


def append_log(line):
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a+", encoding="utf-8") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        fh.seek(0, os.SEEK_END)
        if fh.tell() > MAX_BYTES:
            fh.seek(max(0, fh.tell() - KEEP_BYTES))
            data = fh.read()
            cut = data.find("\n")
            if cut != -1:
                data = data[cut + 1 :]
            fh.seek(0)
            fh.truncate()
            fh.write(data)
        fh.write(line + "\n")
        fh.flush()
    syslog.syslog(syslog.LOG_INFO, line)


def tail_log_text():
    if not LOG.exists():
        return ""
    with LOG.open("rb") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
        fh.seek(0, os.SEEK_END)
        fh.seek(max(0, fh.tell() - 200000))
        return fh.read().decode("utf-8", "replace")


def lookup(ip):
    url = (
        "http://ip-api.com/json/%s?lang=ru&fields=status,country,regionName,city,isp,as"
        % urllib.parse.quote(ip)
    )
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode())
    except Exception:
        return "неизвестно", "неизвестно"
    if data.get("status") != "success":
        return "неизвестно", "неизвестно"
    place = ", ".join(
        part for part in (data.get("country"), data.get("regionName"), data.get("city")) if part
    )
    provider = " / ".join(part for part in (data.get("as"), data.get("isp")) if part)
    return place or "неизвестно", provider or "неизвестно"


class TelegramClient:
    def __init__(self, token):
        self.token = token
        self.conn = None

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    def connect(self):
        self.close()
        infos = socket.getaddrinfo("api.telegram.org", 443, socket.AF_INET, socket.SOCK_STREAM)
        seen = []
        errors = []
        for info in infos:
            ip = info[4][0]
            if ip in seen:
                continue
            seen.append(ip)
            raw = None
            try:
                raw = socket.create_connection((ip, 443), timeout=3)
                raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                raw.settimeout(30)
                wrapped = ssl.create_default_context().wrap_socket(
                    raw, server_hostname="api.telegram.org"
                )
                conn = http.client.HTTPSConnection("api.telegram.org", timeout=30)
                conn.sock = wrapped
                self.conn = conn
                return
            except Exception as exc:
                errors.append("%s: %s" % (ip, exc))
                if raw is not None:
                    try:
                        raw.close()
                    except Exception:
                        pass
        raise RuntimeError("telegram connect failed: " + "; ".join(errors))

    def call(self, method, payload, timeout=20):
        body = json.dumps(payload, ensure_ascii=False).encode()
        path = "/bot%s/%s" % (self.token, method)
        last = None
        for _attempt in (1, 2):
            try:
                if self.conn is None:
                    self.connect()
                self.conn.sock.settimeout(timeout)
                self.conn.request(
                    "POST",
                    path,
                    body,
                    {"Content-Type": "application/json", "Connection": "keep-alive"},
                )
                response = self.conn.getresponse()
                raw = response.read()
                if response.status >= 400:
                    self.close()
                    text = raw.decode("utf-8", "replace")
                    if "message is not modified" in text:
                        return {"ok": True, "description": "message is not modified"}
                    raise RuntimeError("telegram %s %s" % (response.status, text[:300]))
                result = json.loads(raw.decode())
                if not result.get("ok"):
                    raise RuntimeError(result.get("description") or method)
                return result
            except Exception as exc:
                last = exc
                self.close()
        raise last


def api(token, method, payload, timeout=20):
    client = TelegramClient(token)
    try:
        return client.call(method, payload, timeout=timeout)
    finally:
        client.close()


def send(token, chat_id, text, reply_markup=None, parse_mode=None):
    if len(text) > 4000:
        text = text[-4000:]
    payload = {"chat_id": chat_id, "text": text, "disable_notification": False}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    if parse_mode:
        payload["parse_mode"] = parse_mode
    return api(token, "sendMessage", payload)


def edit_text(token, chat_id, message_id, text):
    api(
        token,
        "editMessageText",
        {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text[:4000],
            "parse_mode": "HTML",
        },
        timeout=8,
    )


def alert_text(name, user, ip, stamp, place=None, provider=None):
    lines = [
        "🔴🔴🔴",
        "<b>КТО-ТО НЕ ТОТ ЗАШЁЛ</b>",
        "🔴🔴🔴",
        "",
        "Вход по SSH не из белого списка",
        "Сервер: %s" % html.escape(name),
        "Пользователь: <b>%s</b>" % html.escape(user),
        "IP: <code>%s</code>" % html.escape(ip),
        "Время: %s" % html.escape(stamp),
    ]
    if place is not None:
        lines.append("Место: %s" % html.escape(place))
        lines.append("Провайдер: %s" % html.escape(provider or "неизвестно"))
    return "\n".join(lines)


def set_commands(token):
    api(token, "setMyCommands", {"commands": COMMANDS})


def pending_mode():
    if not PENDING.exists():
        return ""
    return PENDING.read_text(encoding="utf-8").strip()


def set_pending(mode):
    PENDING.parent.mkdir(parents=True, exist_ok=True)
    PENDING.write_text(mode, encoding="utf-8")


def clear_pending():
    PENDING.unlink(missing_ok=True)


def parse_login(line):
    fields = {}
    parts = [part.strip() for part in line.split(" | ")]
    if parts:
        fields["when"] = parts[0]
    for part in parts[2:]:
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    return fields


def short_when(stamp):
    try:
        date, clock = stamp.split(" ", 1)
        _year, month, day = date.split("-")
        hour, minute, second = clock.split(":")[:3]
        second = second.split(" ", 1)[0]
        return "%s.%s %s:%s:%s" % (day, month, hour, minute, second)
    except (ValueError, IndexError):
        return stamp or "время неизвестно"


def short_place(place):
    bits = [bit.strip() for bit in place.split(",") if bit.strip()]
    if len(bits) >= 2 and bits[-1].casefold() == bits[-2].casefold():
        bits.pop(-2)
    if len(bits) >= 2:
        return "%s, %s" % (bits[-1], bits[0])
    return place or "место неизвестно"


def short_provider(provider):
    if " / " in provider:
        _asn, isp = provider.split(" / ", 1)
        isp = isp.strip()
        if isp:
            return isp
    if provider.startswith("AS") and " " in provider:
        return provider.split(" ", 1)[1]
    return provider or "провайдер неизвестен"


def human_bytes(value):
    number = float(value)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if number < 1024 or unit == "ТБ":
            if unit == "Б":
                return "%d %s" % (int(number), unit)
            return "%.1f %s" % (number, unit)
        number /= 1024
    return "%.1f ТБ" % number


def cpu_snapshot():
    parts = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0].split()[1:]
    nums = [int(part) for part in parts]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    return sum(nums), idle


def cpu_percent():
    total_a, idle_a = cpu_snapshot()
    time.sleep(0.3)
    total_b, idle_b = cpu_snapshot()
    total = total_b - total_a
    idle = idle_b - idle_a
    if total <= 0:
        return 0.0
    return max(0.0, min(100.0, (total - idle) * 100.0 / total))


def memory_info():
    info = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        key, _, rest = line.partition(":")
        info[key] = int(rest.strip().split()[0]) * 1024
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", 0)
    swap_total = info.get("SwapTotal", 0)
    swap_free = info.get("SwapFree", 0)
    return total, max(0, total - available), swap_total, max(0, swap_total - swap_free)


def uptime_text():
    seconds = int(float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0]))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    parts = []
    if days:
        parts.append("%d дн" % days)
    parts.append("%d ч" % hours)
    parts.append("%d мин" % minutes)
    return " ".join(parts)


def zone_text():
    zone = "UTC"
    path = Path("/etc/timezone")
    if path.exists():
        zone = path.read_text(encoding="utf-8").strip() or zone
    try:
        proc = subprocess.run(["date", "+%Z %z"], capture_output=True, text=True, timeout=3)
        offset = proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        offset = ""
    return zone if not offset else "%s, %s" % (zone, offset)


def local_ip():
    try:
        proc = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        parts = proc.stdout.split()
        if "src" in parts:
            return parts[parts.index("src") + 1]
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        pass
    return server_name()


def disk_rows():
    try:
        proc = subprocess.run(
            ["df", "-P", "-B1", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    rows = []
    seen = set()
    for line in proc.stdout.splitlines()[1:]:
        bits = line.split()
        if len(bits) < 6:
            continue
        mount = bits[-1]
        if mount in seen:
            continue
        seen.add(mount)
        try:
            total = int(bits[1])
            used = int(bits[2])
            free = int(bits[3])
        except ValueError:
            continue
        rows.append((mount, total, used, free))
    return rows


def site_names():
    text = ""
    try:
        proc = subprocess.run(["nginx", "-T"], capture_output=True, text=True, timeout=8)
        text = proc.stdout + "\n" + proc.stderr
    except (OSError, subprocess.TimeoutExpired):
        text = ""
    if "server_name" not in text:
        chunks = []
        root = Path("/etc/nginx")
        if root.is_dir():
            for path in root.rglob("*"):
                if path.is_file() and path.stat().st_size < 2_000_000:
                    try:
                        chunks.append(path.read_text(encoding="utf-8", errors="replace"))
                    except OSError:
                        continue
        text = "\n".join(chunks)
    skip = {"_", "localhost", "example.com"}
    names = []
    for match in re.finditer(r"server_name\s+([^;]+);", text):
        for name in match.group(1).split():
            name = name.rstrip(".").lower()
            if name in skip or name.startswith("$") or name in names:
                continue
            names.append(name)
    certs = []
    live = Path("/etc/letsencrypt/live")
    if live.is_dir():
        for child in sorted(live.iterdir()):
            if child.is_dir() and child.name != "README" and child.name.lower() not in names:
                certs.append(child.name)
    return names, certs


def status_view():
    name = server_name()
    address = local_ip()
    cfg = load_config()
    place, provider = lookup(address)
    if cfg.get("place"):
        shown_place = cfg["place"]
    else:
        shown_place = short_place(place)
    if cfg.get("provider"):
        provider = cfg["provider"]
    else:
        provider = short_provider(provider)
    load = Path("/proc/loadavg").read_text(encoding="utf-8").split()[:3]
    cores = os.cpu_count() or 1
    percent = cpu_percent()
    mem_total, mem_used, swap_total, swap_used = memory_info()
    disks = disk_rows()
    names, certs = site_names()
    tight = []
    if percent >= 85:
        tight.append("процессор загружен")
    if mem_total and mem_used / mem_total >= 0.9:
        tight.append("мало памяти")
    for mount, total, _used, free in disks:
        if total and free / total < 0.1:
            tight.append("мало места на %s" % mount)
    state = ", ".join(tight) if tight else "норма"
    lines = [
        "<b>%s</b>" % html.escape(name),
        "Состояние: <b>%s</b>" % html.escape(state),
        "Хост: %s" % html.escape(os.uname().nodename),
        "IP: <code>%s</code>" % html.escape(address),
        "Место: %s" % html.escape(shown_place),
        "Часовой пояс: %s" % html.escape(zone_text()),
        "Провайдер: %s" % html.escape(provider),
        "Работает: %s" % html.escape(uptime_text()),
        "CPU: %.0f%%, ядер %d" % (percent, cores),
        "Нагрузка: %s" % html.escape("  ".join(load)),
        "Память: занято %s из %s" % (human_bytes(mem_used), human_bytes(mem_total)),
    ]
    if swap_total:
        lines.append("Swap: занято %s из %s" % (human_bytes(swap_used), human_bytes(swap_total)))
    if disks:
        lines.append("")
        lines.append("<b>Диски</b>")
        for mount, total, _used, free in disks:
            lines.append(
                "%s — свободно %s из %s"
                % (html.escape(mount), human_bytes(free), human_bytes(total))
            )
    lines.append("")
    lines.append("<b>Домены</b>")
    if names:
        lines.extend(html.escape(item) for item in names)
    else:
        lines.append("нет")
    if certs:
        lines.append("")
        lines.append("<b>Сертификаты без сайта</b>")
        lines.extend(html.escape(item) for item in certs)
    lines.append("")
    lines.append(html.escape(now_str()))
    return {
        "text": "\n".join(lines),
        "markup": {"inline_keyboard": [[{"text": "Обновить", "callback_data": "status"}]]},
        "parse_mode": "HTML",
    }


def log_page(page):
    rows = list(reversed(login_lines(tail_log_text(), 64)))
    title = server_name()
    if not rows:
        return {
            "text": "Входов пока нет.\nСервер: %s" % html.escape(title),
            "markup": {"inline_keyboard": []},
            "parse_mode": "HTML",
        }
    pages = (len(rows) + PAGE_SIZE - 1) // PAGE_SIZE
    page = max(0, min(page, pages - 1))
    chunk = rows[page * PAGE_SIZE : (page + 1) * PAGE_SIZE]
    cards = []
    for line in chunk:
        item = parse_login(line)
        clock = short_when(item.get("when", ""))
        user = html.escape(item.get("пользователь", "?"))
        ip = html.escape(item.get("ip", "?"))
        place = html.escape(short_place(item.get("место", "неизвестно")))
        provider = html.escape(short_provider(item.get("провайдер", "неизвестно")))
        mark = "в белом списке" if item.get("белый_список") == "да" else "вне белого списка"
        cards.append(
            "<b>%s</b>  ·  %s\n<b>%s</b>\n<code>%s</code>\n%s\n%s"
            % (clock, mark, user, ip, place, provider)
        )
    start = page * PAGE_SIZE + 1
    end = start + len(chunk) - 1
    text = "<b>Входы %d–%d из %d</b>\n%s\nсначала новые\n\n%s" % (
        start,
        end,
        len(rows),
        html.escape(title),
        "\n\n".join(cards),
    )
    buttons = []
    if page + 1 < pages:
        buttons.append({"text": "← Раньше", "callback_data": "l:%d" % (page + 1)})
    if page > 0:
        buttons.append({"text": "Новее →", "callback_data": "l:%d" % (page - 1)})
    markup = {"inline_keyboard": [buttons] if buttons else []}
    return {"text": text, "markup": markup, "parse_mode": "HTML"}


def login_lines(text, limit=64):
    rows = [line.rstrip("\n") for line in text.splitlines() if "| вход |" in line]
    return rows[-limit:]


def edit_message(client, chat_id, message_id, text, reply_markup=None):
    payload = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text[:4000],
        "parse_mode": "HTML",
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    client.call("editMessageText", payload, timeout=8)


def record():
    if os.environ.get("PAM_SERVICE") != "sshd":
        return
    if os.environ.get("PAM_TYPE") not in (None, "", "open_session"):
        return
    ip = os.environ.get("PAM_RHOST", "").strip()
    user = os.environ.get("PAM_USER", "").strip() or "?"
    if not ip:
        return
    try:
        canon_ip(ip)
    except ValueError:
        return
    stamp = now_str()
    known = {row["ip"] for row in read_entries()}
    listed = ip in known or canon_ip(ip) in known
    syslog.openlog("karaul", syslog.LOG_PID, syslog.LOG_AUTH)
    cfg = None
    message_id = None
    name = ""
    if not listed:
        cfg = load_config()
        name = cfg.get("server") or os.uname().nodename
        try:
            result = send(
                cfg["token"],
                owner_id(cfg),
                alert_text(name, user, ip, stamp),
                parse_mode="HTML",
            )
            message_id = (result.get("result") or {}).get("message_id")
        except Exception as exc:
            append_log("%s | ошибка | telegram | %s" % (now_str(), exc))
    place, provider = lookup(ip)
    append_log(
        "%s | вход | пользователь=%s | ip=%s | место=%s | провайдер=%s | белый_список=%s"
        % (stamp, user, ip, place, provider, "да" if listed else "нет")
    )
    if message_id and cfg:
        try:
            edit_text(
                cfg["token"],
                owner_id(cfg),
                message_id,
                alert_text(name, user, ip, stamp, place, provider),
            )
        except Exception as exc:
            append_log("%s | ошибка | telegram | %s" % (now_str(), exc))


def help_text():
    return (
        "Karaul\n"
        "Сервер: %s\n"
        "Этот бот смотрит только его.\n"
        "/status — загрузка, память, диск, место и домены\n"
        "/list — белый список. Под каждым IP кнопка комментария.\n"
        "/add <ip> [комментарий]\n"
        "/del — выбрать IP и удалить\n"
        "/comment <ip> <текст>\n"
        "/log — последние входы"
        % server_name()
    )


def add_ip(ip, comment=""):
    rows = read_entries()
    for row in rows:
        if row["ip"] == ip:
            append_log("%s | команда | add %s | уже есть" % (now_str(), ip))
            return "Уже в белом списке: " + ip
    rows.append({"ip": ip, "comment": comment[:80]})
    write_entries(rows)
    append_log("%s | команда | add %s | ok" % (now_str(), ip))
    if comment:
        return "Добавлен: %s\n%s" % (ip, comment)
    return "Добавлен: " + ip


def del_ip(ip):
    rows = read_entries()
    kept = [row for row in rows if row["ip"] != ip]
    if len(kept) == len(rows):
        append_log("%s | команда | del %s | нет в списке" % (now_str(), ip))
        return "Нет в белом списке: " + ip
    write_entries(kept)
    append_log("%s | команда | del %s | ok" % (now_str(), ip))
    return "Удалён: " + ip


def set_comment(ip, comment):
    rows = read_entries()
    for row in rows:
        if row["ip"] == ip:
            row["comment"] = comment[:80]
            write_entries(rows)
            append_log("%s | команда | comment %s | ok" % (now_str(), ip))
            return "Комментарий сохранён: %s" % ip
    return "Нет в белом списке: " + ip


def delete_view(notice=""):
    rows = read_entries()
    blocks = ["<b>Удалить IP</b>", html.escape(server_name())]
    if notice:
        blocks.append(html.escape(notice))
    buttons = []
    if not rows:
        blocks.append("Список пуст.")
    else:
        blocks.append("Нажми адрес, который убрать.")
        for index, row in enumerate(rows):
            comment = row["comment"] or "без комментария"
            blocks.append("<code>%s</code>\n%s" % (html.escape(row["ip"]), html.escape(comment)))
            buttons.append([{"text": row["ip"], "callback_data": "d:%d" % index}])
    return {
        "text": "\n\n".join(blocks),
        "markup": {"inline_keyboard": buttons},
        "parse_mode": "HTML",
    }


def delete_confirm(row_index):
    row = read_entries()[row_index]
    comment = row["comment"] or "без комментария"
    return {
        "text": "<b>Удалить этот IP?</b>\n%s\n<code>%s</code>\n%s"
        % (html.escape(server_name()), html.escape(row["ip"]), html.escape(comment)),
        "markup": {
            "inline_keyboard": [
                [
                    {"text": "Удалить", "callback_data": "x:%d" % row_index},
                    {"text": "Оставить", "callback_data": "dlist"},
                ]
            ]
        },
        "parse_mode": "HTML",
    }


def whitelist_view():
    rows = read_entries()
    blocks = ["<b>Белый список</b>", html.escape(server_name()), ""]
    buttons = []
    if not rows:
        blocks.append("Пусто. Нажми «Добавить IP».")
    for index, row in enumerate(rows):
        comment = row["comment"] or "без комментария"
        blocks.append("<code>%s</code>\n%s" % (html.escape(row["ip"]), html.escape(comment)))
        buttons.append([{"text": "✎ " + row["ip"], "callback_data": "n:%d" % index}])
    return {
        "text": "\n\n".join(part for part in blocks if part != ""),
        "markup": {"inline_keyboard": buttons},
        "parse_mode": "HTML",
    }


def handle(text):
    raw = text.strip()
    if raw in BUTTONS:
        raw = BUTTONS[raw]
    if not raw.startswith("/"):
        mode = pending_mode()
        if mode == "add":
            bits = raw.split(None, 1)
            try:
                ip = canon_ip(bits[0])
            except ValueError:
                return "Это не IP. Пришли адрес одним сообщением или нажми другую кнопку."
            comment = bits[1].strip() if len(bits) > 1 else ""
            clear_pending()
            return add_ip(ip, comment)
        if mode.startswith("comment\n") or mode.startswith("comment:"):
            ip = mode.split("\n", 1)[1] if "\n" in mode else mode.split(":", 2)[-1]
            clear_pending()
            return set_comment(ip, "" if raw == "-" else raw)
        return "Нажми кнопку меню или отправь /help"
    clear_pending()
    parts = raw.split()
    cmd = parts[0].split("@", 1)[0].lower()
    arg = parts[1] if len(parts) > 1 else ""
    if cmd in ("/start", "/help"):
        return help_text()
    if cmd == "/status":
        return status_view()
    if cmd == "/list":
        return whitelist_view()
    if cmd == "/add":
        if not arg:
            set_pending("add")
            return "Пришли IP для сервера %s. Можно сразу с комментарием: 1.2.3.4 офис" % server_name()
        bits = raw.split(None, 2)
        try:
            ip = canon_ip(bits[1])
        except ValueError:
            return "Нужен IP. Пример: /add 1.2.3.4 офис"
        comment = bits[2].strip() if len(bits) > 2 else ""
        return add_ip(ip, comment)
    if cmd in ("/del", "/rm"):
        if not arg:
            return delete_view()
        try:
            return del_ip(canon_ip(arg))
        except ValueError:
            return "Нужен IP. Пример: /del 1.2.3.4"
    if cmd == "/comment":
        bits = raw.split(None, 2)
        if len(bits) < 3:
            return "Пример: /comment 1.2.3.4 домашний адрес"
        try:
            ip = canon_ip(bits[1])
        except ValueError:
            return "Нужен IP. Пример: /comment 1.2.3.4 офис"
        return set_comment(ip, bits[2].strip())
    if cmd == "/log":
        return log_page(0)
    if cmd == "/server":
        return "Этот бот смотрит только сервер %s." % server_name()
    return "Неизвестная команда. /help"


def deliver(client, chat_id, result):
    if isinstance(result, dict):
        payload = {"chat_id": chat_id, "text": result["text"][:4000]}
        if result.get("markup"):
            payload["reply_markup"] = result["markup"]
        if result.get("parse_mode"):
            payload["parse_mode"] = result["parse_mode"]
        client.call("sendMessage", payload, timeout=15)
    else:
        payload = {"chat_id": chat_id, "text": result, "reply_markup": KEYBOARD}
        client.call("sendMessage", payload, timeout=8)


def last_number(action):
    parts = action.split(":")
    for part in reversed(parts[1:]):
        if part.isdigit():
            return int(part)
    raise ValueError(action)


def callback_view(action):
    if action in ("servers",) or action.startswith("s:"):
        return {
            "text": "Этот бот смотрит только сервер %s." % html.escape(server_name()),
            "markup": {"inline_keyboard": []},
            "parse_mode": "HTML",
        }
    if action == "status":
        return status_view()
    if action == "dlist" or action.startswith("dlist:"):
        return delete_view()
    if action.startswith("l:"):
        return log_page(last_number(action))
    if action.startswith("d:"):
        try:
            return delete_confirm(last_number(action))
        except IndexError:
            return delete_view("Этого адреса уже нет.")
    if action.startswith("x:"):
        rows = read_entries()
        row_index = last_number(action)
        if row_index >= len(rows):
            return delete_view("Этого адреса уже нет.")
        ip = rows[row_index]["ip"]
        del_ip(ip)
        return delete_view("Удалён: " + ip)
    if action.startswith("n:"):
        rows = read_entries()
        row_index = last_number(action)
        ip = rows[row_index]["ip"]
        set_pending("comment\n" + ip)
        return {
            "text": "Комментарий для %s на %s.\nПришли текст одним сообщением. Минус снимет комментарий."
            % (ip, server_name()),
            "markup": {"inline_keyboard": []},
        }
    return None


def daemon():
    cfg = load_config()
    token = cfg["token"]
    owner = owner_id(cfg)
    syslog.openlog("karaul", syslog.LOG_PID, syslog.LOG_AUTH)
    offset = 0
    if OFFSET.exists():
        try:
            offset = int(OFFSET.read_text(encoding="utf-8").strip() or "0")
        except ValueError:
            offset = 0
    append_log("%s | служба | karaul запущен" % now_str())
    client = TelegramClient(token)
    try:
        client.call("setMyCommands", {"commands": COMMANDS}, timeout=8)
    except Exception as exc:
        syslog.syslog(syslog.LOG_ERR, "setMyCommands: %s" % exc)
    while True:
        try:
            data = client.call(
                "getUpdates",
                {"timeout": 20, "offset": offset, "allowed_updates": ["message", "callback_query"]},
                timeout=35,
            )
            for update in data.get("result", []):
                offset = int(update["update_id"]) + 1
                OFFSET.parent.mkdir(parents=True, exist_ok=True)
                OFFSET.write_text(str(offset), encoding="utf-8")
                callback = update.get("callback_query")
                if callback:
                    message = callback.get("message") or {}
                    chat = message.get("chat") or {}
                    user = callback.get("from") or {}
                    if not from_owner(owner, chat, user):
                        syslog.syslog(syslog.LOG_INFO, "ignored chat %s" % chat.get("id"))
                        continue
                    try:
                        client.call(
                            "answerCallbackQuery",
                            {"callback_query_id": callback["id"]},
                            timeout=5,
                        )
                    except Exception:
                        pass
                    try:
                        view = callback_view(callback.get("data") or "")
                    except (IndexError, ValueError):
                        view = None
                    if view is not None:
                        edit_message(
                            client,
                            owner,
                            message.get("message_id"),
                            view["text"],
                            view.get("markup"),
                        )
                    continue
                message = update.get("message") or update.get("edited_message") or {}
                chat = message.get("chat") or {}
                user = message.get("from") or {}
                if not from_owner(owner, chat, user):
                    syslog.syslog(syslog.LOG_INFO, "ignored chat %s" % chat.get("id"))
                    continue
                text = message.get("text") or ""
                if not text:
                    continue
                deliver(client, owner, handle(text))
        except Exception as exc:
            syslog.syslog(syslog.LOG_ERR, "daemon: %s" % exc)
            client.close()
            time.sleep(1)


if __name__ == "__main__":
    import sys

    mode = sys.argv[1] if len(sys.argv) > 1 else "daemon"
    if mode == "record":
        record()
    elif mode == "whitelist-get":
        sys.stdout.write(WHITELIST.read_text(encoding="utf-8") if WHITELIST.exists() else "")
    elif mode == "whitelist-set":
        write_entries(parse_whitelist_text(sys.stdin.read()))
    elif mode == "log-get":
        sys.stdout.write(tail_log_text())
    elif mode == "log-add":
        syslog.openlog("karaul", syslog.LOG_PID, syslog.LOG_AUTH)
        for line in sys.stdin.read().splitlines():
            if line.strip():
                append_log(line)
    elif mode == "daemon":
        daemon()
    elif mode == "announce":
        cfg = load_config()
        set_commands(cfg["token"])
        send(
            cfg["token"],
            owner_id(cfg),
            "Бот смотрит только сервер %s. Кнопка «Статус» показывает его состояние."
            % cfg.get("server", ""),
            KEYBOARD,
        )
    else:
        raise SystemExit("usage: karaul.py record|daemon|announce")
