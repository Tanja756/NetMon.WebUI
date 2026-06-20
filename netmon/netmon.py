#!/usr/bin/env python3
"""
netmon.py — профессиональный монитор сетевых соединений (htop‑подобный интерфейс).
"""

import socket
import asyncio
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Optional

import psutil
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Header, Footer, Static, DataTable, Input
from textual import events
from textual.widgets._data_table import RowKey
from textual.coordinate import Coordinate
from textual.timer import Timer

from .help_screen import HelpScreen
from .collectors import (
    NetTrafficCollector, LogCollector, get_systemd_service, build_service_map,
    DiskMonitor, NetworkStats, FirewallRules, PortScanDetector,
    WebServerMonitor, DNSMonitor, KillProcess, ProcessTrafficMonitor,
)
from .openvpn_monitor import OpenVPNMonitor


class NetMonitor(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    #topbar {
        height: 3;
        background: $boost;
        color: $text;
        padding: 0 1;
        content-align: left middle;
    }
    #main-layout {
        height: 1fr;
    }
    #left-panel {
        width: 60%;
        border: round $primary;
        padding: 0;
    }
    #right-panel {
        width: 40%;
        border: round $accent;
        padding: 1;
        background: $surface;
    }
    #client-table-container {
        height: 1fr;
        border-top: solid $primary;
        margin: 0;
    }
    #search {
        dock: bottom;
        display: none;
        background: $surface;
        border: solid $primary;
    }
    #status {
        height: 1;
        background: $panel;
        color: $text-muted;
        padding: 0 1;
    }
    #server-detail {
        height: 1fr;
    }
    #info-table {
        height: 4;
        border: round yellow;
        margin: 0 1;
    }
    #login-table {
        height: 10;
        border: round $primary;
        margin: 0 1;
    }
    DataTable {
        height: 1fr;
    }
    #monitors-tabs {
        height: 1;
        background: $boost;
        content-align: left middle;
        padding: 0 1;
    }
    #monitors-content {
        height: 1fr;
        border: round $secondary;
        margin: 0 1;
    }
    """

    update_interval = 2.0
    auto_update = reactive(True)

    def __init__(self):
        super().__init__()
        self.collector = NetTrafficCollector()
        self.openvpn_monitor = OpenVPNMonitor()
        self.log_collector = LogCollector()
        self.disk_monitor = DiskMonitor()
        self.network_stats = NetworkStats()
        self.port_scan_detector = PortScanDetector()
        self.web_server_monitor = WebServerMonitor()
        self.dns_monitor = DNSMonitor()
        self.prev_io: Dict[int, Tuple[int, int]] = {}
        self.servers: List[dict] = []
        self.current_server_key: Optional[Tuple] = None
        self.client_table_visible = True
        self.search_filter = ""
        self.refresh_timer: Optional[Timer] = None
        self._cpu_cache: Dict[int, float] = {}
        self.sort_column = 0
        self.sort_reverse = False
        self.monitor_tab = 0  # 0=disk, 1=network, 2=portscan, 3=firewall, 4=webserver, 5=dns

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Servers: 0 | Clients: 0 | Total traffic: 0 b/s", id="topbar")
        with Horizontal(id="main-layout"):
            with Vertical(id="left-panel"):
                yield DataTable(id="servers-table")
                yield Container(
                    DataTable(id="client-table"),
                    id="client-table-container"
                )
            with Vertical(id="right-panel"):
                yield Static("Select a server", id="server-detail")
                yield Static("TAB|1-6: Dsk Net Scn FW Web DNS", id="monitors-tabs")
                yield Static("(monitor data)", id="monitors-content")
                yield DataTable(id="info-table")
                yield DataTable(id="login-table")
        yield Input(placeholder="Search (PID/name/port)...", id="search")
        yield Static(
            "Space Pause | / Search | S Clients | K Kill | TAB Monitors | ? Help | Q Quit",
            id="status"
        )
        yield Footer()

    def on_mount(self):
        self.table = self.query_one("#servers-table", DataTable)
        self.client_table = self.query_one("#client-table", DataTable)
        self.right_panel = self.query_one("#right-panel", Vertical)
        self.server_detail = self.query_one("#server-detail", Static)
        self.monitors_content = self.query_one("#monitors-content", Static)
        self.monitors_tabs = self.query_one("#monitors-tabs", Static)
        self.search_field = self.query_one("#search", Input)
        self.top_bar = self.query_one("#topbar", Static)
        self.status_bar = self.query_one("#status", Static)

        self.table.add_columns("PID", "PROCESS", "PROTO", "LOCAL", "PORT", "CLIENTS", "RX/s", "TX/s")
        self.table.cursor_type = "row"
        self.table.zebra_stripes = True

        self.client_table.add_columns("Remote Addr", "State", "Client PID")
        self.client_table.zebra_stripes = True

        self.info_table = self.query_one("#info-table", DataTable)
        self.login_table = self.query_one("#login-table", DataTable)
        self.info_table.add_columns("Users", "Sessions", "Failed(1h)", "Uptime")
        self.login_table.add_columns("Time", "IP", "Username", "Status")
        self.login_table.zebra_stripes = True

        # Первичное заполнение
        self._update_login_info()
        self.refresh_timer = self.set_interval(
            self.update_interval, self.refresh_data, pause=not self.auto_update
        )
        self.update_status()

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------
    @staticmethod
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

    @staticmethod
    def format_bytes_float(b: float) -> str:
        if b < 1000:
            return f"{b:.1f}b"
        elif b < 1000 ** 2:
            return f"{b / 1000:.1f}kb"
        elif b < 1000 ** 3:
            return f"{b / (1000 ** 2):.1f}mb"
        elif b < 1000 ** 4:
            return f"{b / (1000 ** 3):.1f}gb"
        else:
            return f"{b / (1000 ** 4):.1f}tb"

    @staticmethod
    def traffic_color(rate: float) -> str:
        if rate > 50 * 1024 * 1024:
            return "red"
        elif rate > 5 * 1024 * 1024:
            return "yellow"
        else:
            return "green"

    @staticmethod
    def client_state_color(state: str) -> str:
        state = state.lower()
        if state == "established":
            return "green"
        elif "time_wait" in state or "close" in state:
            return "dim"
        return "white"

    # ------------------------------------------------------------------
    # Сбор данных
    # ------------------------------------------------------------------
    async def collect_servers_and_clients(self):
        try:
            all_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            self.update_status("No permission, run with sudo")
            return [], 0, (0, 0, 0, 0)

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

        alive_pids = {s[2] for s in servers_raw if s[2]}
        for pid in alive_pids:
            if pid not in self._cpu_cache:
                try:
                    p = psutil.Process(pid)
                    self._cpu_cache[pid] = p.cpu_percent(None)
                except psutil.NoSuchProcess:
                    self._cpu_cache[pid] = 0.0
            else:
                try:
                    p = psutil.Process(pid)
                    self._cpu_cache[pid] = p.cpu_percent(None)
                except psutil.NoSuchProcess:
                    self._cpu_cache[pid] = 0.0
        for pid in list(self._cpu_cache.keys()):
            if pid not in alive_pids:
                del self._cpu_cache[pid]

        servers = []
        total_rx_rate = total_tx_rate = total_rx_cum = total_tx_cum = 0
        for proto, port, pid, name, ip in servers_raw:
            # Берём трафик из nethogs по PID (или 0 если нет данных)
            rx_rate, tx_rate = traffic_by_pid.get(pid, (0.0, 0.0))
            total_rx_rate += rx_rate
            total_tx_rate += tx_rate
            total_rx_cum += rx_rate
            total_tx_cum += tx_rate

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
                    cfg_host, cfg_port = self.openvpn_monitor.find_management_from_config(pid)
                    if cfg_host and cfg_port:
                        mgmt_host, mgmt_port = cfg_host, cfg_port

                ovpn_clients = await self.openvpn_monitor.get_openvpn_clients(pid, mgmt_host, mgmt_port)

                if ovpn_clients:
                    clients_list = [
                        (c["real_address"], "ESTABLISHED", c["common_name"])
                        for c in ovpn_clients
                    ]

            servers.append({
                "pid": pid,
                "name": name,
                "proto": proto,
                "local_ip": ip,
                "port": port,
                "rx_rate": rx_rate,
                "tx_rate": tx_rate,
                "clients": clients_list,
                "client_count": len(clients_list),
                "ovpn_clients": ovpn_clients,
            })
        total_clients = sum(s["client_count"] for s in servers)
        return servers, total_clients, (total_rx_rate, total_tx_rate, total_rx_cum, total_tx_cum)

    # ------------------------------------------------------------------
    # Сбор данных мониторов (фоновый)
    # ------------------------------------------------------------------
    def collect_monitor_data(self) -> str:
        """Собирает данные для активной вкладки монитора и возвращает текст."""
        try:
            if self.monitor_tab == 0:  # Disk
                data = self.disk_monitor.collect()
                return self._render_disk_tui(data)
            elif self.monitor_tab == 1:  # Network
                data = self.network_stats.collect()
                return self._render_network_tui(data)
            elif self.monitor_tab == 2:  # Port scan
                suspicious = self.port_scan_detector.analyze()
                stats = self.port_scan_detector.get_stats()
                return self._render_portscan_tui(suspicious, stats)
            elif self.monitor_tab == 3:  # Firewall
                rules = FirewallRules.get_rules()
                return self._render_firewall_tui(rules)
            elif self.monitor_tab == 4:  # WebServer
                data = self.web_server_monitor.collect()
                return self._render_webserver_tui(data)
            elif self.monitor_tab == 5:  # DNS
                data = self.dns_monitor.collect()
                return self._render_dns_tui(data)
        except Exception as e:
            return f"[red]Error:[/] {e}"
        return ""

    def _render_disk_tui(self, data: dict) -> str:
        disks = data.get("disks", [])
        if not disks:
            return "[dim]No disk data[/]"
        lines = []
        for d in disks:
            pct = d.get("percent", 0)
            color = "red" if pct > 90 else "yellow" if pct > 75 else "green"
            total = self.format_bytes(d.get("total_bytes", 0))
            used = self.format_bytes(d.get("used_bytes", 0))
            free = self.format_bytes(d.get("free_bytes", 0))
            forecast = ""
            if d.get("forecast_hours") is not None:
                forecast = f" | ⏳ ~{d['forecast_hours']}h to full"
            lines.append(
                f"[bold]{d['device']}[/] on [italic]{d['mount']}[/]\n"
                f"  [{color}]■[/] {pct}% Used: {used} / Free: {free} / Total: {total}{forecast}"
            )
        return "\n".join(lines)

    def _render_network_tui(self, data: list) -> str:
        if not data:
            return "[dim]No network interface data[/]"
        lines = []
        for iface in data:
            err = ""
            if iface.get("err_rate_in", 0) > 0 or iface.get("err_rate_out", 0) > 0:
                err += f" [red]⚠ ERR IN:{iface['err_rate_in']}/s OUT:{iface['err_rate_out']}/s[/]"
            if iface.get("drop_rate_in", 0) > 0 or iface.get("drop_rate_out", 0) > 0:
                err += f" [yellow]⬇ DROP IN:{iface['drop_rate_in']}/s OUT:{iface['drop_rate_out']}/s[/]"
            if iface.get("collisions", 0):
                err += f" [red]⚡ COLL:{iface['collisions']}[/]"
            lines.append(
                f"[bold]{iface['name']}[/]\n"
                f"  RX: {self.format_bytes(int(iface['rx_rate']))}/s "
                f"TX: {self.format_bytes(int(iface['tx_rate']))}/s{err}"
            )
        return "\n".join(lines)

    def _render_portscan_tui(self, suspicious: list, stats: dict) -> str:
        lines = [
            f"Tracked IPs: {stats.get('total_ips_tracked', 0)} | "
            f"Ports: {stats.get('total_ports_tracked', 0)} | "
            f"[bold]Suspicious: {stats.get('suspicious_count', 0)}[/]"
        ]
        if not suspicious:
            lines.append("[green]✓ No port scans detected[/]")
        else:
            for s in suspicious:
                lines.append(
                    f"[red]{s['ip']}[/] — [bold]{s['ports_count']} ports[/] "
                    f"[dim]({s['ports'][:10]}{'...' if len(s['ports']) > 10 else ''})[/]"
                )
        return "\n".join(lines)

    def _render_firewall_tui(self, rules: list) -> str:
        if not rules:
            return "[dim]No iptables rules or permission denied[/]"
        chains = defaultdict(list)
        for r in rules:
            chains[r.get("chain", "?")].append(r)
        lines = [f"Total rules: {len(rules)}"]
        for chain, chain_rules in chains.items():
            lines.append(f"\n[bold]{chain}:[/] ({len(chain_rules)} rules)")
            for r in chain_rules[:15]:  # Limit to 15 per chain
                target = r.get("target", "?")
                target_colored = f"[red]{target}[/]" if target.upper() in ("DROP", "REJECT") else f"[green]{target}[/]"
                dport = f" :{r['dport']}" if r.get("dport") else ""
                in_str = f" in:{r['in']}" if r.get("in") and r['in'] != '*' else ""
                out_str = f" out:{r['out']}" if r.get("out") and r['out'] != '*' else ""
                lines.append(
                    f"  [dim]#{r.get('num', '?')}[/] {target_colored} "
                    f"{r.get('prot', '?')}{in_str}{out_str} "
                    f"{r.get('source', '?')}→{r.get('destination', '?')}{dport}"
                )
        return "\n".join(lines)

    def _render_webserver_tui(self, data: dict) -> str:
        if data.get("error"):
            return f"[dim]{data['error']}[/]"
        lines = [
            f"Requests: {data.get('total_requests', 0)} | "
            f"RPS: {data.get('requests_per_second', 0):.1f} | "
            f"[dim]Log: {data.get('log_path', '?')}[/]"
        ]
        if data.get("status_codes"):
            sc = data["status_codes"]
            lines.append(f"Codes: {' | '.join(f'{k}: {v}' for k, v in sorted(sc.items()))}")
        if data.get("top_ips"):
            lines.append(f"\n[bold]Top IPs:[/]")
            for ip in data["top_ips"][:8]:
                lines.append(f"  {ip['ip']} ({ip['count']})")
        if data.get("top_paths"):
            lines.append(f"\n[bold]Top paths:[/]")
            for p in data["top_paths"][:8]:
                lines.append(f"  [dim]{p['path']}[/] ({p['count']})")
        return "\n".join(lines)

    def _render_dns_tui(self, data: dict) -> str:
        if data.get("error"):
            return f"[dim]{data['error']}[/]"
        lines = [f"Type: [bold]{data.get('dns_type', '?')}[/]"]
        if data.get("statistics"):
            for k, v in data["statistics"].items():
                lines.append(f"  {k}: {v}")
        if data.get("queries_per_minute") is not None:
            lines.append(f"  Queries/min: {data['queries_per_minute']:.1f}")
        if data.get("recent_queries") is not None:
            lines.append(f"  Recent queries: {data['recent_queries']}")
        if data.get("captured_packets") is not None:
            lines.append(f"  Captured packets: {data['captured_packets']}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Обновление UI
    # ------------------------------------------------------------------
    def _update_login_info(self):
        au, sess, fail, up, logins = self.log_collector.collect_login_data()
        self.info_table.clear()
        self.info_table.add_row(str(au), str(sess), str(fail), up)
        self.login_table.clear()
        for time_str, ip, user, status in logins:
            color = "red" if status == "Failed" else "green"
            self.login_table.add_row(time_str, ip, user, f"[{color}]{status}[/]")

    async def refresh_data(self):
        servers, total_clients, (total_rx, total_tx, total_rx_cum, total_tx_cum) = \
            await self.collect_servers_and_clients()
        self.servers = servers

        self.top_bar.update(
            f"Servers: {len(servers)} | Clients: {total_clients} | "
            f"⬇ {self.format_bytes(int(total_rx))}/s  ⬆ {self.format_bytes(int(total_tx))}/s | "
            f"Σ⬇ {self.format_bytes(total_rx_cum)}  Σ⬆ {self.format_bytes(total_tx_cum)}"
        )

        self._update_login_info()

        # Обновление мониторов
        monitor_text = self.collect_monitor_data()
        tab_names = ["Disk", "Network", "PortScan", "Firewall", "Web", "DNS"]
        active_tab = tab_names[self.monitor_tab] if self.monitor_tab < len(tab_names) else "?"
        self.monitors_tabs.update(
            f"[bold]{active_tab}[/] | TAB/1-6: Switch | "
            f"D:Disk N:Net P:Scan F:FW W:Web S:DNS"
        )
        self.monitors_content.update(monitor_text)

        filtered = servers
        if self.search_filter:
            flt = self.search_filter.lower()
            filtered = [
                s for s in servers
                if flt in str(s["pid"]).lower()
                or flt in s["name"].lower()
                or flt in str(s["port"])
            ]

        def sort_key(srv):
            col = self.sort_column
            if col == 0:
                return srv["pid"]
            elif col == 1:
                return srv["name"].lower()
            elif col == 2:
                return srv["proto"]
            elif col == 3:
                return srv["local_ip"]
            elif col == 4:
                return srv["port"]
            elif col == 5:
                return srv["client_count"]
            elif col == 6:
                return srv["rx_rate"]
            elif col == 7:
                return srv["tx_rate"]
            return 0
        filtered.sort(key=sort_key, reverse=self.sort_reverse)

        unique_servers = {}
        for srv in filtered:
            key = (srv['pid'], srv['proto'], srv['local_ip'], srv['port'])
            unique_servers.setdefault(key, srv)
        filtered_unique = list(unique_servers.values())

        previous_selected_key = self.current_server_key
        cursor_row_key = None
        scroll_y = self.table.scroll_y
        if self.table.row_count > 0:
            try:
                cursor_row_key = self.table.coordinate_to_cell_key(
                    self.table.cursor_coordinate
                ).row_key
            except Exception:
                pass

        self.table.clear()
        for srv in filtered_unique:
            key = (srv['pid'], srv['proto'], srv['local_ip'], srv['port'])
            rate = max(srv["rx_rate"], srv["tx_rate"])
            color = self.traffic_color(rate)
            rx_str = f"[{color}]{self.format_bytes(int(srv['rx_rate']))}/s[/]"
            tx_str = f"[{color}]{self.format_bytes(int(srv['tx_rate']))}/s[/]"
            self.table.add_row(
                str(srv["pid"]),
                srv["name"],
                srv["proto"],
                srv["local_ip"],
                str(srv["port"]),
                str(srv["client_count"]),
                rx_str,
                tx_str,
                key=key
            )

        restored = False
        if previous_selected_key and self.table.row_count > 0:
            try:
                row_index = self.table.get_row_index(RowKey(previous_selected_key))
                self.table.move_cursor(row=row_index, column=0)
                restored = True
            except KeyError:
                self.current_server_key = None

        if not restored and cursor_row_key is not None and self.table.row_count > 0:
            try:
                row_index = self.table.get_row_index(cursor_row_key)
                self.table.move_cursor(row=row_index, column=0)
                restored = True
            except KeyError:
                pass

        if not restored and self.table.row_count > 0:
            self.table.move_cursor(row=0, column=0)

        if scroll_y < self.table.row_count:
            self.table.scroll_to(y=scroll_y, animate=False)
        else:
            self.table.scroll_to(y=max(0, self.table.row_count - 1), animate=False)

        if self.current_server_key and self.client_table_visible:
            pid, proto, ip, port = self.current_server_key
            for srv in servers:
                if (srv["pid"] == pid and srv["proto"] == proto and
                    srv["local_ip"] == ip and srv["port"] == port):
                    self.show_client_table(srv)
                    break
            else:
                self.clear_client_table()
        else:
            self.clear_client_table()

        self.update_status(f"Updated at {datetime.now().strftime('%H:%M:%S')}")

    # ------------------------------------------------------------------
    # Отображение клиентов
    # ------------------------------------------------------------------
    def show_client_table(self, server: dict):
        if not self.client_table_visible:
            self.clear_client_table(columns=True)
            return

        ovpn_clients = server.get("ovpn_clients", [])
        scroll_y = self.client_table.scroll_y

        if ovpn_clients:
            self.client_table.clear(columns=True)
            self.client_table.add_columns(
                "Common Name", "Remote Address", "RX", "TX", "Connected Since"
            )
            for c in ovpn_clients:
                rx = self.format_bytes(int(c["bytes_received"]))
                tx = self.format_bytes(int(c["bytes_sent"]))
                self.client_table.add_row(
                    c["common_name"],
                    c["real_address"],
                    rx,
                    tx,
                    c["connected_since"],
                )
        else:
            self.client_table.clear(columns=True)
            self.client_table.add_columns("Remote Addr", "State", "Client PID")
            for raddr, state, client_pid in server["clients"]:
                color = self.client_state_color(state)
                self.client_table.add_row(
                    raddr,
                    f"[{color}]{state}[/]",
                    str(client_pid) if client_pid else "-",
                )

        if scroll_y < self.client_table.row_count:
            self.client_table.scroll_to(y=scroll_y, animate=False)
        else:
            self.client_table.scroll_to(y=max(0, self.client_table.row_count - 1), animate=False)

    def clear_client_table(self, columns: bool = False):
        self.client_table.clear(columns=True)

    # ------------------------------------------------------------------
    # Обработчики событий
    # ------------------------------------------------------------------
    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        key = event.row_key
        if key is None:
            return
        pid, proto, ip, port = key.value
        self.current_server_key = (pid, proto, ip, port)
        for srv in self.servers:
            if (srv["pid"] == pid and srv["proto"] == proto and
                srv["local_ip"] == ip and srv["port"] == port):
                self.show_client_table(srv)
                self.show_process_details(srv)
                break

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected):
        if self.sort_column == event.column_index:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = event.column_index
            self.sort_reverse = False
        self.run_worker(self.refresh_data())

    def show_process_details(self, server: dict):
        pid = server["pid"]
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                cpu = self._cpu_cache.get(pid, p.cpu_percent(interval=0))
                mem_mb = p.memory_info().rss // (1024 * 1024)
                threads = p.num_threads()
                user = p.username()
                exe = p.exe() or "?"
                cmdline = " ".join(p.cmdline())
                if len(cmdline) > 2000:
                    cmdline = cmdline[:2000] + "…"
                rx = self.format_bytes(int(server["rx_rate"]))
                tx = self.format_bytes(int(server["tx_rate"]))
            text = f"""
PID:       {pid}
USER:      {user}
PROTO:     {server['proto']}
PORT:      {server['port']}
LOCAL:     {server['local_ip']}

CPU:       {cpu:.1f}%
MEM:       {mem_mb} MB
THREADS:   {threads}

RX rate:   {rx}/s
TX rate:   {tx}/s
[dim]Press K to kill this process[/]

EXE:
{exe}

CMD:
{cmdline}
"""
            self.server_detail.update(text)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.server_detail.update(f"Process {pid} no longer accessible")

    def action_search(self):
        self.search_field.display = True
        self.search_field.focus()

    def on_input_submitted(self, event: Input.Submitted):
        if event.input.id == "search":
            self.search_filter = event.value.strip().lower()
            self.search_field.display = False
            self.run_worker(self.refresh_data())

    def reset_filter(self):
        self.search_filter = ""
        self.search_field.display = False
        self.run_worker(self.refresh_data())

    def action_toggle_update(self):
        self.auto_update = not self.auto_update
        if self.refresh_timer:
            if self.auto_update:
                self.refresh_timer.resume()
            else:
                self.refresh_timer.pause()
        self.update_status()

    def action_toggle_client_table(self):
        self.client_table_visible = not self.client_table_visible
        if self.client_table_visible and isinstance(self.current_server_key, tuple):
            pid, proto, ip, port = self.current_server_key
            for srv in self.servers:
                if (srv["pid"] == pid and srv["proto"] == proto and
                    srv["local_ip"] == ip and srv["port"] == port):
                    self.show_client_table(srv)
                    break
        else:
            self.clear_client_table()
        self.update_status()

    def action_quit(self):
        self.exit()

    def action_show_help(self):
        self.push_screen(HelpScreen())

    def action_kill(self):
        """Kill выбранного процесса."""
        if not self.current_server_key:
            self.update_status("[red]No server selected[/]")
            return
        pid = self.current_server_key[0]
        # Ищем имя процесса
        name = "?"
        for srv in self.servers:
            if srv["pid"] == pid:
                name = srv["name"]
                break
        self.update_status(f"Killing PID {pid} ({name})...")
        result = KillProcess.kill(pid, force=False)
        self.update_status(f"[{'green' if result['success'] else 'red'}]{result['message']}[/]")

    def update_status(self, msg=""):
        if not msg:
            self.status_bar.update(
                f"Auto-update: {'ON' if self.auto_update else 'OFF'} | "
                f"Clients: {'visible' if self.client_table_visible else 'hidden'} | "
                f"Space Pause | / Search | S Clients | K Kill | ? Help | Q Quit"
            )
        else:
            self.status_bar.update(msg)

    def on_key(self, event: events.Key):
        if event.key == "escape" and self.search_field.display:
            self.reset_filter()
        elif event.key == "/":
            self.action_search()
        elif event.key.lower() == "s":
            self.action_toggle_client_table()
        elif event.key == " ":
            self.action_toggle_update()
        elif event.key.lower() == "q":
            self.action_quit()
        elif event.key == "?":
            self.action_show_help()
        elif event.key.lower() == "k":
            self.action_kill()
        elif event.key == "tab":
            self.monitor_tab = (self.monitor_tab + 1) % 6
            self.run_worker(self.refresh_data())
        elif event.key == "1":
            self.monitor_tab = 0
            self.run_worker(self.refresh_data())
        elif event.key == "2":
            self.monitor_tab = 1
            self.run_worker(self.refresh_data())
        elif event.key == "3":
            self.monitor_tab = 2
            self.run_worker(self.refresh_data())
        elif event.key == "4":
            self.monitor_tab = 3
            self.run_worker(self.refresh_data())
        elif event.key == "5":
            self.monitor_tab = 4
            self.run_worker(self.refresh_data())
        elif event.key == "6":
            self.monitor_tab = 5
            self.run_worker(self.refresh_data())
        elif event.key.lower() == "d":
            self.monitor_tab = 0
            self.run_worker(self.refresh_data())
        elif event.key.lower() == "n":
            self.monitor_tab = 1
            self.run_worker(self.refresh_data())
        elif event.key.lower() == "p":
            self.monitor_tab = 2
            self.run_worker(self.refresh_data())
        elif event.key.lower() == "f":
            self.monitor_tab = 3
            self.run_worker(self.refresh_data())
        elif event.key.lower() == "w":
            self.monitor_tab = 4
            self.run_worker(self.refresh_data())
        # 's' is already used for toggle clients, so no 's' for DNS


if __name__ == "__main__":
    app = NetMonitor()
    app.run()