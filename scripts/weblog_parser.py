#!/usr/bin/env python3
"""
Парсинг access-логов веб-сервера (Nginx/Apache).
Вывод статистики в JSON или читаемом виде.

Использование:
    sudo python scripts/weblog_parser.py
    sudo python scripts/weblog_parser.py --path /var/log/nginx/access.log
    sudo python scripts/weblog_parser.py --json
    sudo python scripts/weblog_parser.py --lines 10000 --top 20
"""
import json
import os
import re
import sys
from collections import defaultdict
from typing import Optional, List


COMMON_LOG_PATTERN = re.compile(
    r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]+" (\d+) (\d+|-)'
)


DEFAULT_PATHS = [
    "/var/log/nginx/access.log",
    "/var/log/nginx/access.log.1",
    "/var/log/apache2/access.log",
    "/var/log/apache2/access.log.1",
    "/var/log/httpd/access_log",
    "/var/log/httpd/access.log",
]


def find_logs(path: Optional[str] = None) -> Optional[List[str]]:
    """Возвращает список доступных access-логов.

    Если указан path — возвращает [path] если файл существует и читаем.
    Иначе перебирает DEFAULT_PATHS, собирает все доступные файлы.
    """
    if path:
        return [path] if os.path.exists(path) and os.access(path, os.R_OK) else None
    found = []
    for p in DEFAULT_PATHS:
        if os.path.exists(p) and os.access(p, os.R_OK):
            found.append(p)
    return found if found else None


def parse_log(log_paths: List[str], max_lines: int = 2000) -> dict:
    if isinstance(log_paths, str):
        log_paths = [log_paths]

    # Читаем строки из всех файлов
    merged = []  # list of (log_path, line)
    for log_path in log_paths:
        try:
            with open(log_path) as f:
                for line in f:
                    merged.append((log_path, line))
        except (FileNotFoundError, PermissionError) as e:
            return {"error": str(e), "log_path": log_path}

    # Берём последние max_lines строк из общего пула
    merged = merged[-max_lines:]

    log_path_str = ", ".join(log_paths)

    entries = []
    ip_counts = defaultdict(int)
    path_counts = defaultdict(int)
    status_counts = defaultdict(int)
    total_bytes = 0

    for _log_path, line in merged:
        m = COMMON_LOG_PATTERN.match(line)
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

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)
    recent = entries[-1000:]

    elapsed = 60.0
    rps = len(entries) / elapsed if elapsed > 0 else 0.0

    return {
        "log_path": log_path_str,
        "total_requests": len(entries),
        "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        "top_paths": [{"path": p, "count": c} for p, c in top_paths],
        "status_codes": dict(status_counts),
        "total_bytes": total_bytes,
        "requests_per_second": round(rps, 2),
        "recent_entries": recent,
    }


def fmt_bytes(n: int) -> str:
    for unit in ("b", "kb", "mb", "gb", "tb"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}" if isinstance(n, float) else f"{n}{unit}"
        n /= 1024
    return f"{n:.1f}pb"


def print_human(data: dict, top_n: int = 10):
    if "error" in data:
        print(f"Ошибка: {data['error']}")
        sys.exit(1)

    print(f"Лог-файл:         {data['log_path']}")
    print(f"Всего запросов:   {data['total_requests']}")
    print(f"Запросов/сек:     {data['requests_per_second']}")
    print(f"Передано данных:  {fmt_bytes(data['total_bytes'])}")
    print()

    print("Коды ответов:")
    for code, cnt in sorted(data["status_codes"].items()):
        bar = "#" * min(cnt, 60)
        print(f"  {code}: {cnt:>6} {bar}")
    print()

    print(f"Топ {top_n} IP:")
    for i, entry in enumerate(data["top_ips"][:top_n], 1):
        print(f"  {i:>2}. {entry['ip']:<20} {entry['count']} requests")
    print()

    print(f"Топ {top_n} путей:")
    for i, entry in enumerate(data["top_paths"][:top_n], 1):
        print(f"  {i:>2}. {entry['path']:<40} {entry['count']} requests")
    print()

    print(f"Последние запросы (показано {len(data['recent_entries'])}):")
    for e in data["recent_entries"]:
        print(f"  {e['time']} {e['method']} {e['path']} -> {e['status']} ({e['ip']})")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Парсинг access-логов веб-сервера")
    parser.add_argument("--path", "-p", help="Путь к access-логу")
    parser.add_argument("--lines", "-l", type=int, default=2000, help="Сколько последних строк читать (по умолчанию: 2000)")
    parser.add_argument("--top", "-t", type=int, default=10, help="Сколько позиций показывать в топах (по умолчанию: 10)")
    parser.add_argument("--json", "-j", action="store_true", help="Вывод в JSON")
    args = parser.parse_args()

    log_paths = find_logs(args.path)
    if not log_paths:
        print("Ошибка: access-лог не найден. Укажите --path или убедитесь, что файл существует.", file=sys.stderr)
        sys.exit(1)

    data = parse_log(log_paths, max_lines=args.lines)

    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print_human(data, top_n=args.top)


if __name__ == "__main__":
    main()