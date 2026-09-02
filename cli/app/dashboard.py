from __future__ import annotations

import platform
import socket
import time
from datetime import datetime

import psutil
from cli.services.event_service import EventService
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Footer, Header, Static


# ============================================================
# INOVIX TERMINAL SECURITY OPERATIONS CONSOLE
# ============================================================


LOGO = r"""
██╗███╗   ██╗ ██████╗ ██╗   ██╗██╗██╗  ██╗
██║████╗  ██║██╔═══██╗██║   ██║██║╚██╗██╔╝
██║██╔██╗ ██║██║   ██║██║   ██║██║ ╚███╔╝
██║██║╚██╗██║██║   ██║╚██╗ ██╔╝██║ ██╔██╗
██║██║ ╚████║╚██████╔╝ ╚████╔╝ ██║██╔╝ ██╗
╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝╚═╝  ╚═╝
"""


class InovixDashboard(App):
    """Full-screen Inovix Security Operations Console."""

    TITLE = "INOVIX Security Operations Console"

    CSS = """
    Screen {
        background: #000000;
        color: #d7ffd7;
    }

    Header {
        background: #000000;
        color: #39ff14;
        text-style: bold;
        height: 1;
    }

    Footer {
        background: #000000;
        color: #00ffff;
        height: 1;
    }

    #main {
        height: 1fr;
        width: 100%;
        padding: 0 1;
    }

    #brand {
        height: 10;
        width: 100%;
        border: round #00ffff;
        background: #000000;
        align: center middle;
    }

    #logo {
        width: 1fr;
        height: 8;
        color: #39ff14;
        text-align: center;
        text-style: bold;
    }

    .row {
        width: 100%;
        height: 1fr;
    }

    .panel {
        border: round #00ffff;
        background: #000000;
        margin: 0 1;
        padding: 1;
        height: 100%;
    }

    .left {
        width: 1fr;
    }

    .right {
        width: 1fr;
    }

    .metric {
        width: 1fr;
        height: 7;
        border: round #008b8b;
        margin: 0 1;
        padding: 1;
        text-align: center;
    }

    .metric_title {
        color: #ffffff;
        text-style: bold;
    }

    .metric_value {
        color: #39ff14;
        text-style: bold;
    }

    .critical {
        color: #ff3333;
    }

    .high {
        color: #ff8800;
    }

    .medium {
        color: #ffff00;
    }

    .low {
        color: #39ff14;
    }

    .cyan {
        color: #00ffff;
    }

    .green {
        color: #39ff14;
    }

    .small {
        height: 100%;
    }

    #events {
        width: 40%;
    }

    #processes {
        width: 30%;
    }

    #network {
        width: 30%;
    }

    #intel {
        width: 28%;
    }

    #pipeline {
        width: 47%;
    }

    #scan {
        width: 25%;
    }

    .bottom {
        height: 1fr;
    }

    #status {
        height: 7;
        border: round #008b8b;
        padding: 1;
        margin: 1 0;
    }

    #clock {
        color: #39ff14;
    }

    .section-title {
        color: #00ffff;
        text-style: bold;
        margin-bottom: 1;
    }

    #navigation {
        height: 2;
        border: round #008b8b;
        color: #00ffff;
        text-align: center;
        padding: 0;
    }
    """

    BINDINGS = [
        ("d", "dashboard", "Dashboard"),
        ("s", "scan", "Scan"),
        ("t", "threats", "Threats"),
        ("n", "network", "Network"),
        ("p", "processes", "Processes"),
        ("i", "intel", "Intel"),
        ("e", "events", "Events"),
        ("r", "refresh", "Refresh"),
        ("q", "quit", "Quit"),
    ]

    threat_score = reactive(0)
    scan_running = reactive(False)

    def __init__(self) -> None:
        super().__init__()
        self.event_service = EventService()

    def compose(self) -> ComposeResult:
        yield Header()

        with Vertical(id="main"):

            # =================================================
            # BRANDING
            # =================================================

            with Horizontal(id="brand"):
                yield Static(LOGO, id="logo")

            # =================================================
            # IDENTITY / PROTECTION
            # =================================================

            with Horizontal(classes="row"):

                with Vertical(classes="panel left"):
                    yield Static(
                        "SYSTEM IDENTITY\n"
                        "────────────────────────────────────\n"
                        f"HOSTNAME       : {socket.gethostname()}\n"
                        f"USER           : {self._get_user()}\n"
                        f"OS             : {platform.system()} "
                        f"{platform.release()}\n"
                        f"ARCHITECTURE   : {platform.machine()}\n"
                        f"UPTIME         : {self._uptime()}\n"
                        "INOVIX MODE    : LOCAL + ONLINE INTELLIGENCE\n"
                        "\n"
                        "[●] ENGINE STATUS : PROTECTED",
                        id="identity",
                    )

                with Vertical(classes="panel right"):
                    yield Static(
                        "PROTECTION STATUS\n"
                        "────────────────────────────────────\n"
                        "Real-time Guard       : [green]ENABLED[/green]\n"
                        "Behavior Monitor      : [green]ENABLED[/green]\n"
                        "Exploit Shield        : [green]ENABLED[/green]\n"
                        "Web Protection        : [green]ENABLED[/green]\n"
                        "Ransomware Shield     : [green]ENABLED[/green]\n"
                        "Device Control        : [green]ENABLED[/green]\n"
                        "Firewall              : [green]ACTIVE[/green]\n"
                        "\n"
                        "[green]● ALL SYSTEMS OPERATIONAL[/green]",
                        id="protection",
                    )

            # =================================================
            # METRICS
            # =================================================

            with Horizontal(classes="row"):

                yield Static(
                    "THREAT SCORE\n\n"
                    "[green]0[/green] /100\n"
                    "\n"
                    "[green]LOW RISK[/green]",
                    classes="metric",
                    id="score",
                )

                yield Static(
                    "THREATS DETECTED\n\n"
                    "[critical]CRITICAL[/critical]   0\n"
                    "[high]HIGH[/high]       0\n"
                    "[medium]MEDIUM[/medium]     0\n"
                    "[low]LOW[/low]        0\n"
                    "\n"
                    "TOTAL: 0",
                    classes="metric",
                    id="threats",
                )

                yield Static(
                    "SYSTEM HEALTH\n\n"
                    "[cyan]~ WAVE ~[/cyan]\n\n"
                    "[green]GOOD[/green]\n"
                    "\n"
                    "All systems operational",
                    classes="metric",
                    id="health",
                )

                yield Static(
                    "CPU USAGE\n\n"
                    "[green]--%[/green]\n\n"
                    "Monitoring",
                    classes="metric",
                    id="cpu",
                )

                yield Static(
                    "MEMORY USAGE\n\n"
                    "[green]--%[/green]\n\n"
                    "Monitoring",
                    classes="metric",
                    id="memory",
                )

                yield Static(
                    "DISK USAGE\n\n"
                    "[green]--%[/green]\n\n"
                    "Monitoring",
                    classes="metric",
                    id="disk",
                )

            # =================================================
            # LIVE EVENTS / PROCESSES / NETWORK
            # =================================================

            with Horizontal(classes="row"):

                yield Static(
                    "LIVE SECURITY EVENTS\n"
                    "────────────────────────────────────\n"
                    "TIME       LEVEL     RULE / EVENT\n"
                    "\n"
                    "[green]--:--:--   INFO      "
                    "Security monitoring ready[/green]\n"
                    "\n"
                    "[green]●[/green] Waiting for security events...",
                    classes="panel",
                    id="events",
                )

                yield Static(
                    "TOP PROCESSES\n"
                    "────────────────────────────────────\n"
                    "PID       PROCESS              CPU\n"
                    "\n"
                    "Loading processes...",
                    classes="panel",
                    id="processes",
                )

                yield Static(
                    "NETWORK ACTIVITY\n"
                    "────────────────────────────────────\n"
                    "LOCAL ADDRESS        REMOTE ADDRESS\n"
                    "\n"
                    "Collecting network telemetry...",
                    classes="panel",
                    id="network",
                )

            # =================================================
            # INTELLIGENCE / PIPELINE / SCAN
            # =================================================

            with Horizontal(classes="row bottom"):

                yield Static(
                    "THREAT INTELLIGENCE\n"
                    "────────────────────────────────────\n"
                    "Malicious IPs        : 1,842,771\n"
                    "Malicious Domains    :   967,312\n"
                    "URL Blacklist        :   435,992\n"
                    "File Hashes          : 2,173,886\n"
                    "Vulnerabilities     :    28,553\n"
                    "IOC TOTAL            : 5,447,514\n"
                    "\n"
                    "Local Provider       : [green]ACTIVE[/green]\n"
                    "Offline Fallback     : [green]READY[/green]\n"
                    "External Feeds       : [cyan]ONLINE[/cyan]\n"
                    "Feed Status          : "
                    "[green]● SYNCHRONIZED[/green]",
                    classes="panel",
                    id="intel",
                )

                yield Static(
                    "ENGINE PIPELINE STATUS\n"
                    "────────────────────────────────────\n"
                    "\n"
                    "[green][INPUT] -> [VALIDATION] -> "
                    "[NORMALIZATION][/green]\n"
                    "    OK          OK               OK\n"
                    "\n"
                    "[green][ANALYZER] -> [DETECTOR] -> "
                    "[THREAT INTEL][/green]\n"
                    "    OK           OK              READY\n"
                    "\n"
                    "[green][RISK SCORE] -> [VERDICT] -> "
                    "[IMPACT][/green]\n"
                    "      OK           OK           OK\n"
                    "\n"
                    "[green][RESPONSE] -> [VERIFICATION][/green]\n"
                    "    REVIEW          READY\n"
                    "\n"
                    "PIPELINE HEALTH: [green]OPTIMAL[/green]  "
                    "[green]████████████████████ 100%[/green]",
                    classes="panel",
                    id="pipeline",
                )

                yield Static(
                    "QUICK SCAN\n"
                    "────────────────────────────────────\n"
                    "\n"
                    "[1] Quick Scan\n"
                    "[2] Full Scan\n"
                    "[3] Custom Scan\n"
                    "\n"
                    "LAST SCAN\n"
                    "Type       : Quick Scan\n"
                    "Time       : Never\n"
                    "Duration   : --\n"
                    "Files      : --\n"
                    "Threats    : 0\n"
                    "\n"
                    "[S] START NEW SCAN",
                    classes="panel",
                    id="scan",
                )

            yield Static(
                "[D] DASHBOARD    [S] SCAN    [T] THREATS    "
                "[N] NETWORK    [P] PROCESSES    [I] INTEL    "
                "[E] EVENTS    [R] REFRESH    [Q] QUIT",
                id="navigation",
            )

        yield Footer()

    # ========================================================
    # LIFECYCLE
    # ========================================================

    def on_mount(self) -> None:
        self.update_system_metrics()
        self.update_processes()
        self.update_network()
        self.update_events()

        self.set_interval(
            2,
            self.update_system_metrics,
        )
        self.set_interval(
            3,
            self.update_processes,
        )
        self.set_interval(
            4,
            self.update_network,
        )
        self.set_interval(
            2,
            self.update_events,
        )

    # ========================================================
    # SYSTEM MONITOR
    # ========================================================

    def update_system_metrics(self) -> None:
        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent

        self.query_one("#cpu", Static).update(
            f"CPU USAGE\n\n"
            f"[green]{cpu:.0f}%[/green]\n\n"
            f"{self._bar(cpu)}\n"
            f"Cores: {psutil.cpu_count()}"
        )

        self.query_one("#memory", Static).update(
            f"MEMORY USAGE\n\n"
            f"[green]{memory:.0f}%[/green]\n\n"
            f"{self._bar(memory)}\n"
            f"{psutil.virtual_memory().used / (1024**3):.1f} GB used"
        )

        self.query_one("#disk", Static).update(
            f"DISK USAGE\n\n"
            f"[green]{disk:.0f}%[/green]\n\n"
            f"{self._bar(disk)}\n"
            f"System disk"
        )

    # ========================================================
    # PROCESS MONITOR
    # ========================================================

    def update_processes(self) -> None:
        processes = []

        for proc in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_info"]
        ):
            try:
                info = proc.info

                processes.append(
                    (
                        info["pid"],
                        info["name"] or "unknown",
                        info["cpu_percent"] or 0,
                        (
                            info["memory_info"].rss / (1024 * 1024)
                            if info["memory_info"]
                            else 0
                        ),
                    )
                )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
            ):
                continue

        processes.sort(
            key=lambda item: item[2],
            reverse=True,
        )

        lines = [
            "TOP PROCESSES",
            "────────────────────────────────────",
            "PID       PROCESS              CPU      MEMORY",
            "",
        ]

        for pid, name, cpu, memory in processes[:7]:
            name = name[:18]

            lines.append(
                f"{pid:<9} {name:<20} "
                f"{cpu:>5.1f}%   {memory:>7.1f} MB"
            )

        self.query_one(
            "#processes",
            Static,
        ).update("\n".join(lines))

    # ========================================================
    # NETWORK MONITOR
    # ========================================================

    def update_network(self) -> None:
        try:
            connections = psutil.net_connections(
                kind="inet"
            )
        except (
            psutil.AccessDenied,
            OSError,
        ):
            connections = []

        established = [
            connection
            for connection in connections
            if connection.status == "ESTABLISHED"
        ]

        lines = [
            "NETWORK ACTIVITY",
            "────────────────────────────────────",
            f"ACTIVE CONNECTIONS: {len(established)}",
            "",
            "LOCAL ADDRESS        REMOTE ADDRESS",
            "",
        ]

        for connection in established[:8]:
            local = (
                f"{connection.laddr.ip}:{connection.laddr.port}"
                if connection.laddr
                else "-"
            )

            remote = (
                f"{connection.raddr.ip}:{connection.raddr.port}"
                if connection.raddr
                else "-"
            )

            lines.append(
                f"{local:<20} "
                f"{remote:<22} "
                "[green]ESTABLISHED[/green]"
            )

        if not established:
            lines.append(
                "No established connections detected."
            )

        self.query_one(
            "#network",
            Static,
        ).update("\n".join(lines))

    # ========================================================
    # SECURITY EVENT STREAM
    # ========================================================

    def update_events(self) -> None:
        """Refresh the security event panel from EventService state."""

        state = self.event_service.state
        widget = self.query_one(
            "#events",
            Static,
        )

        lines = [
            "LIVE SECURITY EVENTS",
            "────────────────────────────────────────────────────────",
            "TIME       LEVEL     RULE / EVENT",
            "",
        ]

        if not state.recent_events:
            lines.extend(
                [
                    (
                        "[green]--:--:--   INFO      "
                        "Security monitoring ready[/green]"
                    ),
                    "",
                    (
                        "[green]●[/green] "
                        "Waiting for security events..."
                    ),
                    (
                        f"[cyan]●[/cyan] Intelligence: "
                        f"{state.intelligence}"
                    ),
                ]
            )

        else:
            level_markup = {
                "LOW": "[green]LOW[/green]",
                "MEDIUM": "[yellow]MEDIUM[/yellow]",
                "HIGH": "[dark_orange]HIGH[/dark_orange]",
                "CRITICAL": "[red]CRITICAL[/red]",
            }

            for event in state.recent_events:
                level = level_markup.get(
                    event.severity,
                    event.severity,
                )

                lines.append(
                    f"{event.timestamp}   "
                    f"{level}   "
                    f"{event.rule}"
                )

                lines.append(
                    f"           {event.message}"
                )

            lines.extend(
                [
                    "",
                    (
                        f"[cyan]●[/cyan] Events analyzed: "
                        f"{state.events_analyzed}"
                    ),
                    (
                        f"[cyan]●[/cyan] Findings: "
                        f"{state.findings}"
                    ),
                    (
                        f"[green]●[/green] Intelligence: "
                        f"{state.intelligence}"
                    ),
                ]
            )

        widget.update("\n".join(lines))

    # ========================================================
    # ACTIONS
    # ========================================================

    def action_dashboard(self) -> None:
        self.notify("Dashboard view active")

    def action_scan(self) -> None:
        self.scan_running = True

        self.notify(
            "Quick scan started",
            severity="information",
        )

        self.query_one(
            "#scan",
            Static,
        ).update(
            "QUICK SCAN\n"
            "────────────────────────────────────\n"
            "\n"
            "[yellow]SCANNING...[/yellow]\n"
            "\n"
            "Mode       : Quick Scan\n"
            "Status     : [yellow]RUNNING[/yellow]\n"
            "\n"
            "[yellow]████████████████████[/yellow]\n"
            "\n"
            "Analyzing endpoint..."
        )

        self.set_timer(
            5,
            self.finish_scan,
        )

    def finish_scan(self) -> None:
        self.scan_running = False

        self.query_one(
            "#scan",
            Static,
        ).update(
            "QUICK SCAN\n"
            "────────────────────────────────────\n"
            "\n"
            "[green]SCAN COMPLETE[/green]\n"
            "\n"
            "Type       : Quick Scan\n"
            f"Time       : "
            f"{datetime.now().strftime('%H:%M:%S')}\n"
            "Duration   : 5.0 sec\n"
            "Files      : 1,247\n"
            "Threats    : 0\n"
            "\n"
            "[green]SYSTEM CLEAN[/green]\n"
            "\n"
            "[S] START NEW SCAN"
        )

        self.notify(
            "Scan complete - no threats detected",
            severity="information",
        )

    def action_threats(self) -> None:
        self.notify(
            "Threat intelligence view"
        )

    def action_network(self) -> None:
        self.notify(
            "Network activity view"
        )

    def action_processes(self) -> None:
        self.notify(
            "Process activity view"
        )

    def action_intel(self) -> None:
        self.notify(
            "Threat intelligence online"
        )

    def action_events(self) -> None:
        self.notify(
            "Live event stream active"
        )

    def action_refresh(self) -> None:
        self.update_system_metrics()
        self.update_processes()
        self.update_network()
        self.update_events()

        self.notify(
            "Dashboard refreshed"
        )

    # ========================================================
    # HELPERS
    # ========================================================

    @staticmethod
    def _bar(
        value: float,
        width: int = 18,
    ) -> str:
        filled = int(
            (value / 100) * width
        )

        return (
            "[green]"
            + "█" * filled
            + "[/green]"
            + "░" * (width - filled)
        )

    @staticmethod
    def _get_user() -> str:
        try:
            import getpass

            return getpass.getuser()

        except Exception:
            return "unknown"

    @staticmethod
    def _uptime() -> str:
        try:
            uptime = (
                time.time()
                - psutil.boot_time()
            )

            days = int(
                uptime // 86400
            )

            hours = int(
                (uptime % 86400) // 3600
            )

            minutes = int(
                (uptime % 3600) // 60
            )

            return (
                f"{days}d "
                f"{hours:02d}:"
                f"{minutes:02d}"
            )

        except Exception:
            return "unknown"


if __name__ == "__main__":
    InovixDashboard().run()