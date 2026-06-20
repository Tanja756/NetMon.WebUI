#!/usr/bin/env python3
"""
Запуск API-сервера netmon.
Использование:
    sudo python -m netmon.api_run [--ip IP] [--port PORT]
    sudo python netmon/api_run.py [--ip IP] [--port PORT]

По умолчанию читает конфиг из /etc/netmon/config.json или NETMON_CONFIG.
Если аргументы --ip/--port заданы явно, они переопределяют конфиг.
"""
import sys
import socket
import argparse
import uvicorn
from .config import load_config


def get_local_ips():
    ips = []
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    if addr.address != "127.0.0.1":
                        ips.append((name, addr.address))
    except ImportError:
        pass
    return ips


def print_available_ips():
    ips = get_local_ips()
    print("Доступные IP-адреса для биндинга:")
    print(f"  0) 127.0.0.1 (localhost)")
    for i, (iface, ip) in enumerate(ips, 1):
        print(f"  {i}) {ip} [{iface}]")

    while True:
        try:
            choice = input("\nВыберите номер IP (0 для localhost, или введите свой IP): ").strip()
            if not choice:
                return "127.0.0.1"
            try:
                idx = int(choice)
                if idx == 0:
                    return "127.0.0.1"
                if 1 <= idx <= len(ips):
                    return ips[idx - 1][1]
            except ValueError:
                pass
            try:
                socket.inet_aton(choice)
                return choice
            except socket.error:
                print("  Ошибка: введите номер из списка или корректный IP-адрес")
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(1)


def main():
    cfg = load_config()

    parser = argparse.ArgumentParser(description="NetMonitor API Server")
    parser.add_argument("--ip", "-i",
                        help="IP-адрес для биндинга")
    parser.add_argument("--port", "-p", type=int,
                        help="Порт (по умолчанию: 8000)")
    parser.add_argument("--list", "-l", action="store_true",
                        help="Показать доступные IP и выйти")
    parser.add_argument("--config", "-c",
                        help="Путь к конфигурационному файлу")

    args = parser.parse_args()

    if args.config:
        cfg = load_config(args.config)

    bind_ip = args.ip or cfg.get("host", "0.0.0.0")
    port = args.port or cfg.get("port", 8000)
    log_level = cfg.get("log_level", "info")

    if args.list:
        print_available_ips()
        sys.exit(0)

    if bind_ip == "auto" or not bind_ip:
        bind_ip = print_available_ips()
    else:
        try:
            socket.inet_aton(bind_ip)
        except socket.error:
            print(f"Ошибка: некорректный IP-адрес '{bind_ip}'")
            sys.exit(1)

    print(f"Запуск NetMonitor API на http://{bind_ip}:{port}")
    print(f"Для остановки нажмите Ctrl+C")
    print()

    uvicorn.run(
        "netmon.api_server:app",
        host=bind_ip,
        port=port,
        reload=False,
        log_level=log_level,
    )


if __name__ == "__main__":
    main()