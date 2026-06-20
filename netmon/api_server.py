#!/usr/bin/env python3
"""
API сервер для netmon.
Предоставляет REST API для визуализации данных мониторинга сети.
"""
import asyncio
import os
import socket
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional

import jwt
import psutil
from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from starlette import status

from pathlib import Path
from fastapi.requests import Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .collectors import (
    NetTrafficCollector, LogCollector, get_systemd_service, build_service_map,
    DiskMonitor, NetworkStats, FirewallRules, PortScanDetector,
    WebServerMonitor, DNSMonitor, KillProcess, ProcessTrafficMonitor,
)
from .openvpn_monitor import OpenVPNMonitor
from .auth import init_db, authenticate_user, create_user

app = FastAPI(
    title="NetMonitor API",
    description="REST API для монитора сетевых соединений",
    version="2.0.0",
)

# CORS — разрешаем запросы с любых источников (для визуализации)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Раздача статических файлов (веб-интерфейс)
STATIC_DIR = Path(__file__).resolve().parent.parent / "web"

# Общие экземпляры коллекторов
collector = NetTrafficCollector()
log_collector = LogCollector()
openvpn_monitor = OpenVPNMonitor()
disk_monitor = DiskMonitor()
network_stats = NetworkStats()
port_scan_detector = PortScanDetector()
web_server_monitor = WebServerMonitor()
dns_monitor = DNSMonitor()

# JWT
from .config import load_config
_cfg = load_config()
JWT_SECRET = _cfg.get("jwt_secret", os.environ.get("JWT_SECRET", "netmon-secret-key-change-in-production"))
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = _cfg.get("jwt_expire_hours", 24)

security = HTTPBearer(auto_error=False)

_cpu_cache: Dict[int, float] = {}
_last_call_time: float = 0.0  # время последнего вызова collect_all_data


# Pydantic модели для auth
class AuthLogin(BaseModel):
    username: str
    password: str

class AuthRegister(BaseModel):
    username: str
    password: str

class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


def create_jwt(user_id: int, username: str) -> str:
    """Создаёт JWT токен."""
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> Optional[dict]:
    """Декодирует и валидирует JWT токен. Возвращает payload или None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[dict]:
    """Dependency — возвращает данные пользователя из токена или None (если токена нет)."""
    if credentials is None:
        return None
    payload = decode_jwt(credentials.credentials)
    if payload is None:
        return None
    return {"id": int(payload["sub"]), "username": payload["username"]}


async def require_user(
    current_user: Optional[dict] = Depends(get_current_user),
) -> dict:
    """Dependency — требует аутентификации, иначе 401."""
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user


def format_bytes(b: int) -> str:
    if b < 1000:
        return f"{b}b"
    elif b < 1000 ** 2:
        return f"{b // 1000}kb"
    elif b < 1000 ** 3:
        return f"{b // (1000 ** 2)}mb"
    elif b < 1000 ** 4:
        return f"{b // (1000 ** 3)}gb"
    else:
        return f"{b // (1000 ** 4)}tb"


async def collect_all_data():
    """Собирает все данные: серверы, клиенты, трафик."""
    global _cpu_cache, _last_call_time

    now = time.time()

    try:
        all_conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return {"error": "No permission, run with sudo"}

    # Имена процессов — получаем карту сервисов один раз
    service_map = build_service_map()
    proc_names = {}
    for p in psutil.process_iter(["pid", "name"]):
        pid = p.info["pid"]
        name = p.info["name"] or "unknown"
        try:
            service = get_systemd_service(pid, service_map)
            if service:
                name = f"{name} ({service})"
        except Exception:
            pass
        proc_names[pid] = name

    servers_raw = []
    server_addrs = set()
    server_pids = set()

    for conn in all_conns:
        if not conn.laddr:
            continue
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        ip, port = conn.laddr
        pid = conn.pid or 0
        name = proc_names.get(pid, "?")
        if proto == "TCP" and conn.status == "LISTEN":
            servers_raw.append((proto, port, pid, name, ip))
            server_addrs.add((proto, ip, port))
            server_pids.add((proto, ip, port, pid))
        elif proto == "UDP":
            if not conn.raddr or conn.raddr.ip in ("0.0.0.0", "::") or conn.raddr.port == 0:
                servers_raw.append((proto, port, pid, name, ip))
                server_addrs.add((proto, ip, port))
                server_pids.add((proto, ip, port, pid))

    server_index = defaultdict(list)
    for proto, port, pid, name, ip in servers_raw:
        server_index[(proto, ip, port)].append((pid, name))

    clients_map = defaultdict(list)
    for conn in all_conns:
        if not conn.laddr:
            continue
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        ip, port = conn.laddr
        pid = conn.pid or 0
        if (proto, ip, port, pid) in server_pids:
            continue
        match_key = None
        if (proto, ip, port) in server_addrs:
            match_key = (proto, ip, port)
        else:
            for srv_ip in ("0.0.0.0", "::"):
                if (proto, srv_ip, port) in server_addrs:
                    match_key = (proto, srv_ip, port)
                    break
        if match_key:
            for srv_pid, srv_name in server_index[match_key]:
                if conn.laddr == (ip, port) and conn.pid == srv_pid:
                    continue
                matched = (proto, srv_pid, port)
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "*:*"
                state = conn.status if conn.status else "-"
                clients_map[matched].append((raddr, state, conn.pid or 0))

    # Per-PID трафик через nethogs (один вызов для всех процессов)
    traffic_by_pid = ProcessTrafficMonitor.get_traffic_by_pid()

    # CPU
    alive_pids = {s[2] for s in servers_raw if s[2]}
    for pid in alive_pids:
        try:
            p = psutil.Process(pid)
            _cpu_cache[pid] = p.cpu_percent(interval=0)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            _cpu_cache[pid] = 0.0
    for pid in list(_cpu_cache.keys()):
        if pid not in alive_pids:
            del _cpu_cache[pid]

    _last_call_time = now

    servers = []
    total_rx_rate = total_tx_rate = 0

    for proto, port, pid, name, ip in servers_raw:
        # Берём трафик из nethogs по PID (или 0 если нет данных)
        rx_rate, tx_rate = traffic_by_pid.get(pid, (0.0, 0.0))
        total_rx_rate += rx_rate
        total_tx_rate += tx_rate
        clients_list = clients_map.get((proto, pid, port), [])

        is_openvpn = (name.lower() == "openvpn") or ("openvpn" in name.lower())
        if not is_openvpn and pid:
            try:
                p = psutil.Process(pid)
                cmdline_lower = " ".join(p.cmdline()).lower()
                if "openvpn" in cmdline_lower or "ovpn-server" in cmdline_lower:
                    is_openvpn = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        ovpn_clients = []
        if is_openvpn and pid:
            mgmt_host = "127.0.0.1"
            mgmt_port = 5555
            found = False
            try:
                p = psutil.Process(pid)
                cmdline = p.cmdline()
                for i, arg in enumerate(cmdline):
                    if arg == "--management" and i + 2 < len(cmdline):
                        mgmt_host = cmdline[i + 1]
                        try:
                            mgmt_port = int(cmdline[i + 2])
                            found = True
                        except ValueError:
                            pass
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            if not found:
                cfg_host, cfg_port = openvpn_monitor.find_management_from_config(pid)
                if cfg_host and cfg_port:
                    mgmt_host, mgmt_port = cfg_host, cfg_port

            ovpn_clients = await openvpn_monitor.get_openvpn_clients(pid, mgmt_host, mgmt_port)

            if ovpn_clients:
                clients_list = [
                    {"address": c["real_address"], "state": "ESTABLISHED", "common_name": c["common_name"]}
                    for c in ovpn_clients
                ]
            else:
                clients_list = [{"address": addr, "state": state, "pid": cpid}
                                for addr, state, cpid in clients_list]
        else:
            clients_list = [{"address": addr, "state": state, "pid": cpid}
                            for addr, state, cpid in clients_list]

        # Детали процесса
        proc_detail = None
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                cpu = _cpu_cache.get(pid, 0.0)
                mem_bytes = p.memory_info().rss
                threads = p.num_threads()
                username = p.username()
                exe = p.exe() or "?"
                cmdline = " ".join(p.cmdline())
            proc_detail = {
                "cpu_percent": round(cpu, 1),
                "memory_bytes": mem_bytes,
                "threads": threads,
                "username": username,
                "exe": exe,
                "cmdline": cmdline[:2000] if len(cmdline) > 2000 else cmdline,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        servers.append({
            "pid": pid,
            "name": name,
            "proto": proto,
            "local_ip": ip,
            "port": port,
            "rx_rate": rx_rate,
            "tx_rate": tx_rate,
            "rx_rate_formatted": format_bytes(int(rx_rate)) + "/s",
            "tx_rate_formatted": format_bytes(int(tx_rate)) + "/s",
            "clients": clients_list,
            "client_count": len(clients_list),
            "is_openvpn": is_openvpn,
            "process": proc_detail,
        })

    total_clients = sum(s["client_count"] for s in servers)

    return {
        "servers": servers,
        "summary": {
            "server_count": len(servers),
            "client_count": total_clients,
            "total_rx_rate": total_rx_rate,
            "total_tx_rate": total_tx_rate,
            "total_rx_rate_formatted": format_bytes(int(total_rx_rate)) + "/s",
            "total_tx_rate_formatted": format_bytes(int(total_tx_rate)) + "/s",
            "total_rx_bytes": int(total_rx_rate),
            "total_tx_bytes": int(total_tx_rate),
            "total_rx_bytes_formatted": format_bytes(int(total_rx_rate)),
            "total_tx_bytes_formatted": format_bytes(int(total_tx_rate)),
        }
    }


@app.on_event("startup")
async def startup():
    """При старте API: инициализируем БД пользователей."""
    init_db()


# ---------------------------------------------------------------------------
# Endpoints — основные
# ---------------------------------------------------------------------------

@app.get("/api/servers")
async def get_servers(current_user: dict = Depends(require_user)):
    """Возвращает список всех слушающих серверов с данными о трафике и клиентах."""
    result = await collect_all_data()
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=403, detail=result["error"])
    return result


@app.get("/api/servers/{pid}/{proto}/{ip}/{port}")
async def get_server_detail(pid: int, proto: str, ip: str, port: int, current_user: dict = Depends(require_user)):
    """Возвращает детальную информацию по конкретному серверу."""
    result = await collect_all_data()
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=403, detail=result["error"])
    for srv in result["servers"]:
        if srv["pid"] == pid and srv["proto"] == proto and srv["local_ip"] == ip and srv["port"] == port:
            return srv
    raise HTTPException(status_code=404, detail="Server not found")


@app.get("/api/login-info")
async def get_login_info(current_user: dict = Depends(require_user)):
    """Возвращает информацию о входах: пользователи, сессии, неудачные попытки, uptime."""
    au, sess, fail, up, logins = log_collector.collect_login_data()
    return {
        "active_users": au,
        "active_sessions": sess,
        "failed_last_hour": fail,
        "uptime": up,
        "recent_logins": [
            {"time": t, "ip": ip, "username": u, "status": s}
            for t, ip, u, s in logins
        ],
    }


@app.get("/api/summary")
async def get_summary(current_user: dict = Depends(require_user)):
    """Возвращает краткую сводку по системе."""
    result = await collect_all_data()
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=403, detail=result["error"])

    au, sess, fail, up, _ = log_collector.collect_login_data()

    return {
        "summary": result["summary"],
        "login": {
            "active_users": au,
            "active_sessions": sess,
            "failed_last_hour": fail,
            "uptime": up,
        },
    }


@app.get("/api/health")
async def health():
    """Проверка работоспособности API."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.post("/api/auth/login", response_model=AuthResponse)
async def login(data: AuthLogin):
    """Аутентификация пользователя. Возвращает JWT токен."""
    user = authenticate_user(data.username, data.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    token = create_jwt(user["id"], user["username"])
    return AuthResponse(access_token=token, username=user["username"])


@app.post("/api/auth/register")
async def register(data: AuthRegister):
    """Регистрация нового пользователя."""
    if len(data.username) < 2:
        raise HTTPException(status_code=400, detail="Username must be at least 2 characters")
    if len(data.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    success = create_user(data.username, data.password)
    if not success:
        raise HTTPException(status_code=409, detail="User already exists")
    return {"message": "User created successfully", "username": data.username}


@app.get("/api/auth/me")
async def me(current_user: dict = Depends(require_user)):
    """Возвращает данные текущего аутентифицированного пользователя."""
    return current_user


# ---------------------------------------------------------------------------
# Endpoints — новые мониторы
# ---------------------------------------------------------------------------

@app.get("/api/disk")
async def get_disk_info(current_user: dict = Depends(require_user)):
    """Информация о дисках: usage, I/O, прогноз заполнения."""
    return disk_monitor.collect()


@app.get("/api/network")
async def get_network_stats(current_user: dict = Depends(require_user)):
    """Статистика по сетевым интерфейсам: ошибки, дропы, коллизии."""
    return {"interfaces": network_stats.collect()}


@app.get("/api/firewall")
async def get_firewall_rules(port: Optional[int] = Query(None, description="Фильтр по порту"), current_user: dict = Depends(require_user)):
    """Правила iptables/nftables. Можно отфильтровать по порту."""
    rules = FirewallRules.get_rules(for_port=port)
    return {"rules_count": len(rules), "rules": rules}


@app.get("/api/port-scans")
async def get_port_scans(current_user: dict = Depends(require_user)):
    """Детектор сканирования портов: IP, подключившиеся к большому числу портов."""
    suspicious = port_scan_detector.analyze()
    stats = port_scan_detector.get_stats()
    return {"suspicious": suspicious, "stats": stats}


@app.get("/api/webserver")
async def get_webserver_stats(current_user: dict = Depends(require_user)):
    """Статистика веб-сервера (Nginx/Apache) из access-логов."""
    return web_server_monitor.collect()


@app.get("/api/dns")
async def get_dns_stats(current_user: dict = Depends(require_user)):
    """Статистика DNS-запросов."""
    return dns_monitor.collect()


@app.post("/api/kill/{pid}")
async def kill_process(pid: int, force: bool = Query(False, description="SIGKILL если SIGTERM не помог"), current_user: dict = Depends(require_user)):
    """Отправить сигнал завершения процессу."""
    result = KillProcess.kill(pid, force=force)
    if not result["success"]:
        raise HTTPException(status_code=403, detail=result["message"])
    return result


@app.get("/api/all")
async def get_all_monitors(current_user: dict = Depends(require_user)):
    """Возвращает данные со всех мониторов одним запросом."""
    # Запускаем все сборщики параллельно
    servers_task = asyncio.create_task(collect_all_data())
    login_task = asyncio.create_task(
        asyncio.to_thread(log_collector.collect_login_data)
    )
    disk_task = asyncio.create_task(
        asyncio.to_thread(disk_monitor.collect)
    )
    network_task = asyncio.create_task(
        asyncio.to_thread(network_stats.collect)
    )
    portscan_task = asyncio.create_task(
        asyncio.to_thread(port_scan_detector.analyze)
    )
    portscan_stats_task = asyncio.create_task(
        asyncio.to_thread(port_scan_detector.get_stats)
    )
    webserver_task = asyncio.create_task(
        asyncio.to_thread(web_server_monitor.collect)
    )
    dns_task = asyncio.create_task(
        asyncio.to_thread(dns_monitor.collect)
    )

    servers_result = await servers_task
    au, sess, fail, up, logins = await login_task
    disk_data = await disk_task
    network_data = await network_task
    portscan_data = await portscan_task
    portscan_stats_data = await portscan_stats_task
    webserver_data = await webserver_task
    dns_data = await dns_task

    result = {
        "servers": servers_result.get("servers", []),
        "summary": servers_result.get("summary", {}),
        "login": {
            "active_users": au,
            "active_sessions": sess,
            "failed_last_hour": fail,
            "uptime": up,
            "recent_logins": [
                {"time": t, "ip": ip, "username": u, "status": s}
                for t, ip, u, s in logins
            ],
        },
        "disk": disk_data,
        "network": {"interfaces": network_data},
        "port_scans": {
            "suspicious": portscan_data,
            "stats": portscan_stats_data,
        },
        "webserver": webserver_data,
        "dns": dns_data,
    }

    if isinstance(servers_result, dict) and "error" in servers_result:
        result["error"] = servers_result["error"]

    return result


@app.get("/{full_path:path}")
async def serve_static(full_path: str):
    """Отдаёт статические файлы. По умолчанию login.html."""
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not found")
    
    # Корень всегда отдаёт login.html
    if full_path == "" or full_path == "/":
        login_file = STATIC_DIR / "login.html"
        if login_file.exists():
            return FileResponse(str(login_file))
        raise HTTPException(status_code=404, detail="Not found")
    
    # Запрашиваемый файл
    requested = STATIC_DIR / full_path
    if requested.exists() and requested.is_file():
        return FileResponse(str(requested))
    
    # Всё остальное — login.html
    login_file = STATIC_DIR / "login.html"
    if login_file.exists():
        return FileResponse(str(login_file))
    raise HTTPException(status_code=404, detail="Not found")
