#!/usr/bin/env python3
"""
Коллекторы данных для NetMonitor.
"""
import os
import re
import time
import signal
import socket
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Optional

import psutil


# ======================================================================
# Вспомогательные функции
# ======================================================================

_MONTHS = ["jan", "feb", "mar", "apr", "may", "jun",
            "jul", "aug", "sep", "oct", "nov", "dec"]


def _parse_timestamp(line: str) -> Optional[datetime]:
    """Парсит ISO-таймстемп из journalctl (с учётом timezone и микросекунд)."""
    m = re.match(
        r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)',
        line
    )
    if m:
        try:
            return datetime.fromisoformat(m.group(1))
        except Exception:
            pass
    return None


def _parse_syslog_ts(line: str) -> Optional[datetime]:
    """Парсит syslog-таймстемп (Jan  1 12:34:56)."""
    try:
        parts = line.split()
        if len(parts) < 3:
            return None
        mon_str = parts[0].lower()[:3]
        if mon_str not in _MONTHS:
            return None
        mon = _MONTHS.index(mon_str) + 1
        day = int(parts[1])
        time_str = parts[2]
        now = datetime.now()
        h, m, s = map(int, time_str.split(":"))
        return datetime(now.year, mon, day, h, m, s)
    except Exception:
        return None


def _parse_auth_line(line: str) -> Optional[Tuple[datetime, str, str, str]]:
    """Парсит строку auth-лога.
    Возвращает (timestamp, ip, username, status) или None.
    """
    ts = _parse_timestamp(line)
    if ts is None:
        ts = _parse_syslog_ts(line)
    if ts is None:
        return None

    # Failed password for invalid user
    if "Failed password for invalid user" in line:
        parts = line.split()
        try:
            return (ts, parts[parts.index("from") + 1], parts[parts.index("user") + 1], "Failed")
        except (ValueError, IndexError):
            return None

    # Failed password for (valid) user
    if "Failed password for" in line and "invalid" not in line:
        parts = line.split()
        try:
            return (ts, parts[parts.index("from") + 1], parts[parts.index("for") + 1], "Failed")
        except (ValueError, IndexError):
            return None

    # Accepted password
    if "Accepted password for" in line:
        parts = line.split()
        try:
            return (ts, parts[parts.index("from") + 1], parts[parts.index("for") + 1], "Accepted")
        except (ValueError, IndexError):
            return None

    # Accepted publickey (через regex — устойчивее к вариациям OpenSSH)
    if "Accepted publickey" in line:
        m = re.search(r'Accepted publickey for (\S+) from (\S+)', line)
        if m:
            return (ts, m.group(2), m.group(1), "Accepted")
        return None

    # Invalid user (без "Failed password" — строки вида "Invalid user admin from 1.2.3.4")
    if "Invalid user" in line:
        m = re.search(r'Invalid user (\S+) from (\S+)', line)
        if m:
            return (ts, m.group(2), m.group(1), "Failed")

    # authentication failure (с ; из journalctl и без ; из auth.log)
    if "authentication failure" in line:
        parts = line.split()
        user = "?"
        ip = "?"
        for i, p in enumerate(parts):
            if p.startswith("rhost="):
                ip = p.split("=", 1)[1]
            elif p.startswith("user="):
                user = p.split("=", 1)[1]
        if user != "?" or ip != "?":
            return (ts, ip, user, "Failed")

    return None


def _run_journalctl(cmd: list) -> list:
    """Запускает journalctl и парсит строки."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        entries = []
        for line in result.stdout.splitlines():
            if line.startswith("Hint:") or line.startswith("--"):
                continue
            parsed = _parse_auth_line(line)
            if parsed:
                entries.append(parsed)
        return entries
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _read_auth_log(path: str) -> list:
    """Читает auth.log напрямую."""
    try:
        with open(path) as f:
            entries = []
            for line in f:
                parsed = _parse_auth_line(line)
                if parsed:
                    entries.append(parsed)
            return entries
    except (FileNotFoundError, PermissionError):
        return []


def _run_sudo(cmd: list) -> list:
    """Запускает команду через sudo -n."""
    try:
        full_cmd = ["sudo", "-n"] + cmd
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return []
        return result.stdout.splitlines()
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return []


# Глобальный кэш для сервисов (обновляется раз в несколько секунд)
_service_cache: dict = {}
_service_cache_time: float = 0.0


def get_systemd_service(pid: int, service_map: Optional[dict] = None) -> Optional[str]:
    """
    Быстрое определение systemd-сервиса по PID.
    Сначала пробует cgroup (самый надёжный способ), затем — кэш service_map.
    """
    if service_map is not None and pid in service_map:
        return service_map[pid]

    # 1) Прямой парсинг /proc/<pid>/cgroup (работает всегда)
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            for line in f:
                # systemd slice: /system.slice/ssh.service
                m = re.search(r'/system\.slice/([\w@.:-]+\.service)', line)
                if m:
                    return m.group(1)
                # user slice: /user.slice/user-1000.slice/session-1.scope/...  (иногда сервисы там)
                m = re.search(r'/user\.slice/.*?/([\w@.:-]+\.service)', line)
                if m:
                    return m.group(1)
                # docker / podman контейнеры (если нужно)
                m = re.search(r'/docker/([a-f0-9]+)/', line)
                if m:
                    return f"docker-{m.group(1)[:12]}"
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass

    # 2) Если cgroup не дал результата — пробуем systemctl status (один раз для всех)
    if service_map is None:
        # вызовем build_service_map один раз и закэшируем глобально
        global _service_cache, _service_cache_time
        if not _service_cache or (time.time() - _service_cache_time) > 5.0:
            _service_cache = build_service_map(force_refresh=False)
        service_map = _service_cache

    return service_map.get(pid)


def build_service_map(force_refresh: bool = False) -> dict:
    """
    Строит словарь {pid: service_name} для всех запущенных systemd-сервисов.
    Использует systemctl show --property=MainPID,Id для всех сервисов разом (один вызов).
    """
    global _service_cache, _service_cache_time
    now = time.time()
    if not force_refresh and (now - _service_cache_time) < 5.0:
        return _service_cache

    service_map = {}
    try:
        # 1) Получаем список всех активных сервисов (один вызов)
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running",
             "--no-pager", "--no-legend"],
            capture_output=True, text=True, timeout=3
        )
        service_names = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts and parts[0].endswith(".service"):
                service_names.append(parts[0])

        if service_names:
            # 2) Одним вызовом systemctl show получаем MainPID для всех
            result2 = subprocess.run(
                ["systemctl", "show", "--property=Id,MainPID"] + service_names,
                capture_output=True, text=True, timeout=5
            )
            current_id = None
            for line in result2.stdout.splitlines():
                if line.startswith("Id="):
                    current_id = line.split("=", 1)[1]
                elif line.startswith("MainPID="):
                    pid_str = line.split("=", 1)[1]
                    if current_id and pid_str.isdigit() and int(pid_str) > 0:
                        service_map[int(pid_str)] = current_id
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    _service_cache = service_map
    _service_cache_time = now
    return service_map


def get_uptime() -> str:
    """Возвращает uptime системы в читаемом формате."""
    try:
        with open("/proc/uptime") as f:
            uptime_sec = float(f.read().split()[0])
        days = int(uptime_sec // 86400)
        hours = int((uptime_sec % 86400) // 3600)
        minutes = int((uptime_sec % 3600) // 60)
        parts = []
        if days > 0: parts.append(f"{days}d")
        if hours > 0: parts.append(f"{hours}h")
        parts.append(f"{minutes}m")
        return " ".join(parts)
    except Exception:
        return "?"


def get_login_attempts() -> Tuple[int, int, int, str, list]:
    """
    Анализирует логи входа (journalctl, /var/log/auth.log, last).
    Возвращает (active_users, active_sessions, failed_last_hour, uptime, logins).

    logins — список кортежей (datetime_or_str, ip, username, status).
    """
    uptime_str = get_uptime()

    # Активные пользователи и сессии через psutil
    users = psutil.users()
    active_users = len(set(u.name for u in users))
    active_sessions = len(users)

    login_attempts = []  # list of (datetime, ip, user, status)

    # 1) journalctl -u sshd (sshd.service)
    login_attempts = _run_journalctl(
        ["journalctl", "-u", "sshd", "-n", "500", "--no-pager", "-o", "short-iso"]
    )

    # 2) ssh.service (на Debian/Ubuntu может быть ssh, а не sshd)
    if not login_attempts:
        login_attempts = _run_journalctl(
            ["journalctl", "-u", "ssh", "-n", "500", "--no-pager", "-o", "short-iso"]
        )

    # 3) _COMM=sshd (оригинальный фильтр — всё ещё работает на многих системах)
    if not login_attempts:
        login_attempts = _run_journalctl(
            ["journalctl", "_COMM=sshd", "-n", "500", "--no-pager", "-o", "short-iso"]
        )

    # 4) Если journalctl не дал результатов — пробуем с sudo
    if not login_attempts:
        for unit in ["sshd", "ssh"]:
            login_attempts = _run_journalctl(
                ["sudo", "-n", "journalctl", "-u", unit, "-n", "500", "--no-pager", "-o", "short-iso"]
            )
            if login_attempts:
                break

    # 5) Если всё ещё нет — читаем /var/log/auth.log напрямую
    if not login_attempts:
        for path in ["/var/log/auth.log", "/var/log/secure", "/var/log/auth.log.1"]:
            login_attempts = _read_auth_log(path)
            if login_attempts:
                break

    # 4) Если auth.log не читается — пробуем sudo cat
    if not login_attempts:
        for path in ["/var/log/auth.log", "/var/log/secure", "/var/log/auth.log.1"]:
            lines = _run_sudo(["cat", path])
            for line in lines:
                parsed = _parse_auth_line(line)
                if parsed:
                    login_attempts.append(parsed)
            if login_attempts:
                break

    # 5) Если всё ещё нет логов — пробуем who
    if not login_attempts:
        try:
            result = subprocess.run(
                ["who", "-u"],
                capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5:
                    username = parts[0]
                    ip = parts[-1] if parts[-1] != "." else "local"
                    ip = ip.strip("()")
                    login_attempts.append((datetime.now(), ip, username, "Accepted"))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Подсчёт неудачных попыток за последний час
    now = time.time()
    failed_last_hour = sum(
        1 for ts, _, _, status in login_attempts
        if isinstance(ts, datetime) and status == "Failed" and (now - ts.timestamp()) < 3600
    )

    # Форматируем для отображения
    display = []
    for ts, ip, user, status in reversed(login_attempts[-50:]):
        if isinstance(ts, datetime):
            time_str = ts.strftime("%H:%M")
        else:
            time_str = str(ts)
        display.append((time_str, ip, user, status))

    return active_users, active_sessions, failed_last_hour, uptime_str, display


# ======================================================================
# LogCollector — информация о входах в систему
# ======================================================================
class LogCollector:
    """
    Собирает информацию о входах в систему, активных сессиях и неудачных попытках.
    """

    def __init__(self):
        self._last_users: Optional[set] = None

    def collect_login_data(self) -> Tuple[int, int, int, str, list]:
        """
        Возвращает (active_users, active_sessions, failed_last_hour, uptime, list_of_logins).
        """
        return get_login_attempts()


# ======================================================================
# NetTrafficCollector — сбор данных о трафике процессов
# ======================================================================
class NetTrafficCollector:
    """Сборщик сетевого трафика по PID через /proc/<pid>/net/dev."""

    def get_process_io(self, pid: int) -> Tuple[int, int]:
        """
        Возвращает (rx_bytes, tx_bytes) — системные счётчики сетевых интерфейсов.
        
        ВНИМАНИЕ: /proc/<pid>/net/dev в стандартном network namespace показывает
        одинаковые глобальные счётчики для всех PID (per-process сетевой мониторинг
        невозможен без eBPF/nethogs). Поэтому используем psutil.net_io_counters(),
        исключая loopback (lo), где RX всегда равен TX.
        """
        try:
            io_counters = psutil.net_io_counters(pernic=True)
            rx_total = tx_total = 0
            for name, counters in io_counters.items():
                if name in ("lo", "lo0"):
                    continue
                rx_total += counters.bytes_recv
                tx_total += counters.bytes_sent
            return rx_total, tx_total
        except Exception:
            return 0, 0


# ======================================================================
# DiskMonitor — мониторинг дисков
# ======================================================================
class DiskMonitor:
    """
    Мониторинг дисков: использование, I/O, прогноз заполнения.
    """

    def collect(self) -> dict:
        partitions = []
        try:
            for part in psutil.disk_partitions():
                if part.device.startswith("/dev/"):
                    try:
                        usage = psutil.disk_usage(part.mountpoint)
                        # Простейший прогноз заполнения
                        forecast = None
                        try:
                            io = psutil.disk_io_counters(perdisk=True)
                            if part.device.replace("/dev/", "") in io:
                                dio = io[part.device.replace("/dev/", "")]
                                if dio.write_bytes > 0:
                                    write_rate = dio.write_bytes / 60.0
                                    if write_rate > 0:
                                        remaining = usage.free
                                        forecast = int(remaining / write_rate) if write_rate > 0 else None
                        except Exception:
                            pass
                        partitions.append({
                            "device": part.device,
                            "mount": part.mountpoint,
                            "fstype": part.fstype,
                            "total_bytes": usage.total,
                            "used_bytes": usage.used,
                            "free_bytes": usage.free,
                            "percent": usage.percent,
                            "forecast_hours": forecast,
                        })
                    except PermissionError:
                        pass
        except Exception:
            pass
        # I/O статистика
        io_data = {}
        try:
            io = psutil.disk_io_counters(perdisk=True)
            for disk, counters in io.items():
                io_data[disk] = {
                    "read_bytes": counters.read_bytes,
                    "write_bytes": counters.write_bytes,
                    "read_count": counters.read_count,
                    "write_count": counters.write_count,
                }
        except Exception:
            pass
        return {
            "disks": partitions,
            "io": io_data,
        }


# ======================================================================
# NetworkStats — статистика сетевых интерфейсов
# ======================================================================
class NetworkStats:
    """
    Мониторинг сетевых интерфейсов: ошибки, дропы, коллизии, скорость.
    """

    def __init__(self):
        self._prev = {}

    def collect(self) -> list:
        interfaces = []
        now = time.time()
        try:
            io_counters = psutil.net_io_counters(pernic=True)
            for name, counters in io_counters.items():
                prev_data = self._prev.get(name)
                if prev_data:
                    dt = now - prev_data["time"]
                    err_rate_in = (counters.errin - prev_data["errin"]) / dt if dt > 0 else 0
                    err_rate_out = (counters.errout - prev_data["errout"]) / dt if dt > 0 else 0
                    drop_rate_in = (counters.dropin - prev_data["dropin"]) / dt if dt > 0 else 0
                    drop_rate_out = (counters.dropout - prev_data["dropout"]) / dt if dt > 0 else 0
                    rx_rate = (counters.bytes_recv - prev_data["rx"]) / dt if dt > 0 else 0
                    tx_rate = (counters.bytes_sent - prev_data["tx"]) / dt if dt > 0 else 0
                else:
                    err_rate_in = err_rate_out = drop_rate_in = drop_rate_out = rx_rate = tx_rate = 0

                self._prev[name] = {
                    "time": now,
                    "errin": counters.errin,
                    "errout": counters.errout,
                    "dropin": counters.dropin,
                    "dropout": counters.dropout,
                    "rx": counters.bytes_recv,
                    "tx": counters.bytes_sent,
                }

                interfaces.append({
                    "name": name,
                    "rx_rate": rx_rate,
                    "tx_rate": tx_rate,
                    "err_in": counters.errin,
                    "err_out": counters.errout,
                    "err_rate_in": err_rate_in,
                    "err_rate_out": err_rate_out,
                    "drop_in": counters.dropin,
                    "drop_out": counters.dropout,
                    "drop_rate_in": drop_rate_in,
                    "drop_rate_out": drop_rate_out,
                    "collisions": counters.collisions,
                })
        except Exception:
            pass
        return interfaces


# ======================================================================
# FirewallRules — получение правил iptables/nftables
# ======================================================================
class FirewallRules:
    """Получение правил фаервола."""

    @staticmethod
    def get_rules(for_port: Optional[int] = None) -> list:
        """
        Парсит iptables -L и возвращает список правил в структурированном виде.
        """
        rules = []
        raw = FirewallRules._get_raw_rules()
        if not raw:
            return rules
        current_chain = None
        for line in raw.splitlines():
            if line.startswith("Chain "):
                m = re.match(r'Chain (\S+)', line)
                if m:
                    current_chain = m.group(1)
                continue
            if not line.strip() or line.startswith("target"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            num = parts[0]
            target = parts[1]
            prot = parts[2]
            source = parts[3]
            destination = parts[4] if len(parts) > 4 else ""
            # Опциональные поля: in, out, dport
            in_ = ""
            out_ = ""
            dport = None
            extra = " ".join(parts[5:]) if len(parts) > 5 else ""
            m_in = re.search(r'in\s+(\S+)', extra)
            if m_in:
                in_ = m_in.group(1)
            m_out = re.search(r'out\s+(\S+)', extra)
            if m_out:
                out_ = m_out.group(1)
            m_dport = re.search(r'dpt:(\d+)', extra)
            if m_dport:
                dport = int(m_dport.group(1))
            rule = {
                "chain": current_chain,
                "num": num,
                "target": target,
                "prot": prot,
                "source": source,
                "destination": destination,
                "in": in_,
                "out": out_,
                "dport": dport,
            }
            if for_port is None or dport == for_port:
                rules.append(rule)
        return rules

    @staticmethod
    def _get_raw_rules() -> str:
        """Пытается выполнить iptables -L с sudo или без."""
        try:
            result = subprocess.run(
                ["iptables", "-L", "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                return result.stdout
        except FileNotFoundError:
            pass
        try:
            result = subprocess.run(
                ["sudo", "-n", "iptables", "-L", "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                return result.stdout
        except Exception:
            pass
        return ""

    @staticmethod
    def _extract_dport(line: str) -> Optional[int]:
        """Извлекает порт назначения из строки правила iptables."""
        m = re.search(r'dpt:(\d+)', line)
        if m:
            return int(m.group(1))
        m = re.search(r'(\b|:)dports?[=:](\d+)', line, re.IGNORECASE)
        if m:
            return int(m.group(2))
        return None


# ======================================================================
# PortScanDetector — детектор частых подключений с одного IP к разным портам
# ======================================================================
class PortScanDetector:
    """
    Детектирует сканирование портов с одного IP.
    Ведёт историю подключений за последние N секунд.
    """

    def __init__(self, window: int = 60, threshold: int = 10):
        self.window = window          # окно в секундах
        self.threshold = threshold    # порог разных портов
        self._history: Dict[str, Dict[int, float]] = defaultdict(dict)
        # {ip: {port: timestamp}}

    def analyze(self) -> List[dict]:
        """
        Анализирует текущие соединения и возвращает список подозрительных IP.
        """
        # Очистка устаревших записей
        now = time.time()
        cutoff = now - self.window

        for ip in list(self._history.keys()):
            for port in list(self._history[ip].keys()):
                if self._history[ip][port] < cutoff:
                    del self._history[ip][port]
            if not self._history[ip]:
                del self._history[ip]

        # Сбор новых соединений
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return []

        for conn in conns:
            if not conn.raddr or not conn.raddr.ip:
                continue
            ip = conn.raddr.ip
            port = conn.raddr.port
            if ip and port:
                self._history[ip][port] = now

        # Выявление подозрительных
        suspicious = []
        for ip, ports in self._history.items():
            if len(ports) >= self.threshold:
                suspicious.append({
                    "ip": ip,
                    "ports_count": len(ports),
                    "ports": sorted(ports.keys()),
                    "first_seen": min(ports.values()),
                    "last_seen": max(ports.values()),
                })

        suspicious.sort(key=lambda x: x["ports_count"], reverse=True)
        return suspicious

    def get_stats(self) -> dict:
        """Возвращает общую статистику детектора."""
        total_ips = len(self._history)
        total_ports = sum(len(ports) for ports in self._history.values())
        suspicious = sum(1 for ports in self._history.values() if len(ports) >= self.threshold)
        return {
            "total_ips_tracked": total_ips,
            "total_ports_tracked": total_ports,
            "suspicious_count": suspicious,
        }


# ======================================================================
# WebServerMonitor — Nginx/Apache: парсинг access-логов
# ======================================================================
class WebServerMonitor:
    """Парсинг access-логов Nginx/Apache и сбор статистики."""

    COMMON_LOG_PATTERN = re.compile(
        r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]+" (\d+) (\d+|-)'
    )

    def __init__(self, max_lines: int = 2000):
        self.max_lines = max_lines
        self._log_paths = self._find_logs()

    def _find_logs(self) -> Optional[List[str]]:
        """Возвращает список доступных access-логов.

        Сначала пробует определить через PID процесса — собирает все файлы,
        соответствующие найденному серверу (access.log + access.log.1).
        Fallback: проверяет существование стандартных путей.
        """
        # Сначала пробуем определить через PID процесса
        for p in psutil.process_iter(["pid", "name"]):
            name = (p.info["name"] or "").lower()
            if name in ("nginx", "httpd", "apache2", "apache"):
                try:
                    cmdline = " ".join(p.cmdline()).lower()
                    found = []
                    # Nginx
                    if "nginx" in name or "nginx" in cmdline:
                        for path in [
                            "/var/log/nginx/access.log",
                            "/var/log/nginx/access.log.1",
                        ]:
                            if os.path.exists(path) and os.access(path, os.R_OK):
                                found.append(path)
                        return found if found else None
                    # Apache
                    if "apache" in name or "httpd" in name or "apache" in cmdline:
                        for path in [
                            "/var/log/apache2/access.log",
                            "/var/log/apache2/access.log.1",
                            "/var/log/httpd/access_log",
                            "/var/log/httpd/access.log",
                            "/var/log/httpd/access.log.1",
                        ]:
                            if os.path.exists(path) and os.access(path, os.R_OK):
                                found.append(path)
                        return found if found else None
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        # Fallback: проверить существование — собираем все доступные
        found = []
        for path in [
            "/var/log/nginx/access.log",
            "/var/log/nginx/access.log.1",
            "/var/log/apache2/access.log",
            "/var/log/apache2/access.log.1",
            "/var/log/httpd/access_log",
            "/var/log/httpd/access.log",
            "/var/log/httpd/access.log.1",
        ]:
            if os.path.exists(path) and os.access(path, os.R_OK):
                found.append(path)
        return found if found else None

    def collect(self) -> dict:
        """Парсит лог(и) и возвращает статистику."""
        if not self._log_paths:
            return {"error": "Access log not found"}

        # Читаем строки из всех файлов
        merged = []  # list of (log_path, line)
        for log_path in self._log_paths:
            try:
                with open(log_path) as f:
                    for line in f:
                        merged.append((log_path, line))
            except (FileNotFoundError, PermissionError) as e:
                return {"error": str(e), "log_path": log_path}

        # Берём последние max_lines строк из общего пула
        merged = merged[-self.max_lines:]

        log_path_str = ", ".join(self._log_paths)

        entries = []
        ip_counts = defaultdict(int)
        path_counts = defaultdict(int)
        status_counts = defaultdict(int)
        total_bytes = 0

        for _log_path, line in merged:
            m = self.COMMON_LOG_PATTERN.match(line)
            if not m:
                continue
            ip = m.group(1)
            ts = m.group(2)
            method = m.group(3)
            path = m.group(4)
            status = int(m.group(5))
            bytes_str = m.group(6)

            ip_counts[ip] += 1
            path_counts[path] += 1
            status_counts[status] += 1

            try:
                total_bytes += int(bytes_str) if bytes_str != "-" else 0
            except ValueError:
                pass

            entries.append({
                "ip": ip,
                "time": ts,
                "method": method,
                "path": path,
                "status": status,
                "bytes": bytes_str,
            })

        # Топ IP, топ путей, коды ответов
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:40]
        top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:40]
        recent_entries = entries[-100:]

        return {
            "log_path": log_path_str,
            "total_requests": len(entries),
            "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
            "top_paths": [{"path": p, "count": c} for p, c in top_paths],
            "status_codes": dict(status_counts),
            "total_bytes": total_bytes,
            "requests_per_second": len(entries) / 60.0,
            "recent_entries": recent_entries,
        }


# ======================================================================
# DNSMonitor — отслеживание DNS-запросов
# ======================================================================
class DNSMonitor:
    """
    Мониторинг DNS-запросов через systemd-resolved, journalctl или BIND log.
    """

    def __init__(self):
        self._dns_type = self._detect_dns_type()

    @staticmethod
    def _detect_dns_type() -> str:
        """Определяет, какой DNS-сервер используется."""
        # systemd-resolved
        try:
            result = subprocess.run(
                ["resolvectl", "statistics"],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                return "systemd-resolved"
        except FileNotFoundError:
            pass

        # BIND
        for path in ["/var/log/named.log", "/var/log/bind9/query.log"]:
            if os.path.exists(path):
                return "bind"

        # journalctl
        try:
            result = subprocess.run(
                ["journalctl", "-u", "systemd-resolved", "-n", "1", "--no-pager"],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0 and result.stdout.strip():
                return "journalctl"
        except FileNotFoundError:
            pass

        # Fallback: tcpdump
        try:
            subprocess.run(["tcpdump", "--version"], capture_output=True, timeout=1)
            return "tcpdump"
        except FileNotFoundError:
            pass

        return "none"

    def collect(self) -> dict:
        """Собирает DNS-статистику."""
        if self._dns_type == "systemd-resolved":
            return self._collect_resolved()
        elif self._dns_type in ("journalctl",):
            return self._collect_journalctl()
        elif self._dns_type == "bind":
            return self._collect_bind()
        elif self._dns_type == "tcpdump":
            return self._collect_tcpdump()
        return {"error": f"No DNS monitor available ({self._dns_type})", "dns_type": self._dns_type}

    def _collect_resolved(self) -> dict:
        """Статистика через resolvectl."""
        try:
            result = subprocess.run(
                ["resolvectl", "statistics"],
                capture_output=True, text=True, timeout=3
            )
            stats = {}
            for line in result.stdout.splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    stats[key.strip().lower().replace(" ", "_")] = val.strip()
            return {"dns_type": "systemd-resolved", "statistics": stats}
        except Exception as e:
            return {"error": str(e), "dns_type": "systemd-resolved"}

    def _collect_journalctl(self) -> dict:
        """Парсинг journalctl для systemd-resolved."""
        try:
            result = subprocess.run(
                ["journalctl", "-u", "systemd-resolved", "-n", "200", "--no-pager", "-o", "short-iso"],
                capture_output=True, text=True, timeout=5
            )
            queries = []
            for line in result.stdout.splitlines():
                if "Transaction" in line and "query" in line.lower():
                    queries.append(line.strip())

            return {
                "dns_type": "journalctl",
                "recent_queries": len(queries),
                "queries_per_minute": len(queries) / 5 if queries else 0,
                "raw_lines": queries[-30:],
            }
        except Exception as e:
            return {"error": str(e), "dns_type": "journalctl"}

    def _collect_bind(self) -> dict:
        """Парсинг лога BIND."""
        for path in ["/var/log/named.log", "/var/log/bind9/query.log"]:
            try:
                with open(path) as f:
                    lines = f.readlines()[-500:]
                queries = []
                for line in lines:
                    if "query:" in line.lower() or "queries:" in line.lower():
                        queries.append(line.strip())
                return {
                    "dns_type": "bind",
                    "log_path": path,
                    "recent_queries": len(queries),
                    "raw_lines": queries[-30:],
                }
            except (FileNotFoundError, PermissionError):
                continue
        return {"error": "BIND log not found", "dns_type": "bind"}

    def _collect_tcpdump(self) -> dict:
        """Захват DNS-пакетов через tcpdump (без установки scapy)."""
        try:
            result = subprocess.run(
                ["tcpdump", "-c", "50", "-i", "any", "port", "53", "-n", "-t", "-q"],
                capture_output=True, text=True, timeout=3
            )
            lines = [l for l in result.stdout.splitlines() if l.strip()]
            return {
                "dns_type": "tcpdump",
                "captured_packets": len(lines),
                "raw_lines": lines[-20:],
            }
        except subprocess.TimeoutExpired:
            return {"dns_type": "tcpdump", "captured_packets": 50, "note": "limit reached"}
        except Exception as e:
            return {"error": str(e), "dns_type": "tcpdump"}


# ======================================================================
# ProcessTrafficMonitor — per-PID трафик через nethogs
# ======================================================================
class ProcessTrafficMonitor:
    """Мониторинг трафика по PID через nethogs."""

    @staticmethod
    def get_traffic_by_pid() -> Dict[int, Tuple[float, float]]:
        """
        Запускает nethogs и возвращает словарь {pid: (rx_bps, tx_bps)}.
        Требует установленного nethogs и прав root.
        Возвращает пустой словарь, если nethogs не доступен.
        """
        try:
            # nethogs -t (только трафик) -c 1 (один цикл) -d 1 (интервал 1 сек)
            cmd = ["nethogs", "-t", "-c", "1", "-d", "1"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            lines = result.stdout.splitlines()
            # Пример строки: "eth0   1234.56   5678.90   /usr/sbin/nginx  1234"
            # Формат: интерфейс, RX KB/s, TX KB/s, процесс, PID
            traffic = {}
            for line in lines:
                if not line.strip() or line.startswith("Refreshing"):
                    continue
                parts = line.split()
                if len(parts) >= 5:
                    # последний элемент — PID, предпоследний — имя процесса
                    pid_str = parts[-1]
                    try:
                        pid = int(pid_str)
                        rx_kb = float(parts[1])
                        tx_kb = float(parts[2])
                        traffic[pid] = (rx_kb * 1024, tx_kb * 1024)  # переводим в байты/с
                    except (ValueError, IndexError):
                        continue
            return traffic
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            return {}


# ======================================================================
# KillProcess — принудительная остановка процесса по PID
# ======================================================================
class KillProcess:
    """Безопасное завершение процесса."""

    @staticmethod
    def kill(pid: int, force: bool = False) -> dict:
        """
        Отправляет сигнал процессу.
        Сначала SIGTERM, через 3 секунды SIGKILL если force=True.
        Возвращает {'success': True/False, 'message': str}.
        """
        try:
            p = psutil.Process(pid)
            name = p.name()
        except psutil.NoSuchProcess:
            return {"success": False, "message": f"Process {pid} not found"}

        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            if force:
                time.sleep(2.5)
                try:
                    p = psutil.Process(pid)
                    os.kill(pid, signal.SIGKILL)
                    return {
                        "success": True,
                        "message": f"Process {pid} ({name}) killed with SIGKILL (SIGTERM ignored)",
                    }
                except psutil.NoSuchProcess:
                    return {
                        "success": True,
                        "message": f"Process {pid} ({name}) terminated with SIGTERM",
                    }
            else:
                return {
                    "success": True,
                    "message": f"Signal SIGTERM sent to {pid} ({name})",
                }
        except PermissionError:
            return {"success": False, "message": f"Permission denied to kill {pid} ({name})"}
        except ProcessLookupError:
            return {"success": True, "message": f"Process {pid} already exited"}
        except Exception as e:
            return {"success": False, "message": str(e)}