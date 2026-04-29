#!/usr/bin/env python3
"""
NetScope - Network Traffic Analyzer
Parses PCAP files and web server logs to produce traffic insights.
"""

import sys
import os
import re
import json
import argparse
import subprocess
import shutil
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Optional

# ── Rich (pretty CLI) ──────────────────────────────────────────────────────────
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
from rich import box
from rich.text import Text
from rich.columns import Columns

console = Console()

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class TrafficStats:
    total_packets: int = 0
    total_bytes: int = 0
    protocols: Counter = field(default_factory=Counter)
    src_ips: Counter = field(default_factory=Counter)
    dst_ips: Counter = field(default_factory=Counter)
    src_ports: Counter = field(default_factory=Counter)
    dst_ports: Counter = field(default_factory=Counter)
    packet_sizes: list = field(default_factory=list)
    timeline: list = field(default_factory=list)   # list of (timestamp, bytes)
    flags: Counter = field(default_factory=Counter) # TCP flags
    dns_queries: Counter = field(default_factory=Counter)
    http_methods: Counter = field(default_factory=Counter)
    status_codes: Counter = field(default_factory=Counter)
    user_agents: Counter = field(default_factory=Counter)
    source: str = "unknown"
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


# ── PCAP Parser ───────────────────────────────────────────────────────────────

def parse_pcap(path: str) -> TrafficStats:
    """Parse a .pcap or .pcapng file using tshark field extraction."""
    if not shutil.which("tshark"):
        console.print("[red]tshark not found. Install Wireshark/tshark first.[/red]")
        sys.exit(1)

    stats = TrafficStats(source=path)
    console.print(f"[cyan]Reading PCAP:[/cyan] {path}")

    fields = [
        "frame.time_epoch",
        "frame.len",
        "ip.src", "ip.dst",
        "ip.proto",
        "tcp.srcport", "tcp.dstport",
        "udp.srcport", "udp.dstport",
        "tcp.flags.str",
        "dns.qry.name",
        "http.request.method",
        "http.response.code",
    ]
    field_args = []
    for f in fields:
        field_args += ["-e", f]

    cmd = ["tshark", "-r", path, "-T", "fields", "-E", "separator=|",
           "-E", "occurrence=f"] + field_args

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        console.print("[red]tshark timed out reading file.[/red]")
        sys.exit(1)

    lines = result.stdout.strip().splitlines()
    console.print(f"[dim]Parsing {len(lines):,} packets via tshark…[/dim]")

    proto_map = {"6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMPv6",
                 "47": "GRE", "50": "ESP", "132": "SCTP"}

    for line in track(lines, description="Analysing packets…"):
        cols = (line + "|" * len(fields)).split("|")
        (ts_raw, frame_len, ip_src, ip_dst, ip_proto,
         tcp_sport, tcp_dport, udp_sport, udp_dport,
         tcp_flags, dns_name, http_method, http_status) = cols[:13]

        # bytes / size
        try:
            size = int(frame_len)
        except ValueError:
            size = 0
        stats.total_packets += 1
        stats.total_bytes += size
        stats.packet_sizes.append(size)

        # timestamp
        try:
            ts = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc)
            if stats.start_time is None or ts < stats.start_time:
                stats.start_time = ts
            if stats.end_time is None or ts > stats.end_time:
                stats.end_time = ts
            stats.timeline.append((ts.isoformat(), size))
        except (ValueError, OSError):
            pass

        # IPs
        if ip_src:
            stats.src_ips[ip_src] += 1
        if ip_dst:
            stats.dst_ips[ip_dst] += 1

        # Protocol
        proto_label = proto_map.get(ip_proto, f"proto/{ip_proto}" if ip_proto else "Other")
        stats.protocols[proto_label] += 1

        # TCP
        if tcp_sport:
            try:
                stats.src_ports[int(tcp_sport)] += 1
            except ValueError:
                pass
        if tcp_dport:
            try:
                stats.dst_ports[int(tcp_dport)] += 1
            except ValueError:
                pass
        # TCP flags  e.g. "·······A····" or "··S·····"
        if tcp_flags:
            flag_chars = {"S": "SYN", "A": "ACK", "F": "FIN",
                          "R": "RST", "P": "PSH", "U": "URG"}
            for ch, name in flag_chars.items():
                if ch in tcp_flags:
                    stats.flags[name] += 1

        # UDP
        if udp_sport:
            try:
                stats.src_ports[int(udp_sport)] += 1
            except ValueError:
                pass
        if udp_dport:
            try:
                stats.dst_ports[int(udp_dport)] += 1
            except ValueError:
                pass

        # DNS
        if dns_name:
            stats.dns_queries[dns_name.rstrip(".")] += 1

        # HTTP
        if http_method:
            stats.http_methods[http_method] += 1
        if http_status:
            stats.status_codes[http_status] += 1

    return stats


# ── Log Parser ────────────────────────────────────────────────────────────────

# Combined Log Format (Apache / Nginx)
LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)?\s*(?P<path>\S*)?\s*\S*"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

def parse_log(path: str) -> TrafficStats:
    """Parse Apache/Nginx combined access logs."""
    stats = TrafficStats(source=path)
    lines = Path(path).read_text(errors="replace").splitlines()

    for line in track(lines, description="Parsing log lines…"):
        m = LOG_RE.match(line)
        if not m:
            continue
        g = m.groupdict()

        stats.total_packets += 1
        size = int(g["size"]) if g["size"] and g["size"] != "-" else 0
        stats.total_bytes += size
        stats.packet_sizes.append(size)

        stats.src_ips[g["ip"]] += 1
        stats.protocols["HTTP"] += 1

        if g["method"]:
            stats.http_methods[g["method"]] += 1
        if g["status"]:
            stats.status_codes[g["status"]] += 1
        if g["agent"] and g["agent"] != "-":
            # Condense user-agent to browser family
            ua = g["agent"]
            if "Chrome" in ua:   family = "Chrome"
            elif "Firefox" in ua: family = "Firefox"
            elif "Safari" in ua:  family = "Safari"
            elif "curl" in ua:    family = "curl"
            elif "python" in ua.lower(): family = "Python"
            elif "bot" in ua.lower() or "crawler" in ua.lower(): family = "Bot/Crawler"
            else:                 family = "Other"
            stats.user_agents[family] += 1

        try:
            ts = datetime.strptime(g["time"].split()[0], "%d/%b/%Y:%H:%M:%S")
            ts = ts.replace(tzinfo=timezone.utc)
            if stats.start_time is None or ts < stats.start_time:
                stats.start_time = ts
            if stats.end_time is None or ts > stats.end_time:
                stats.end_time = ts
            stats.timeline.append((ts.isoformat(), size))
        except ValueError:
            pass

    return stats


# ── Display ───────────────────────────────────────────────────────────────────

def fmt_bytes(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def top_table(title: str, counter: Counter, top: int = 10,
              col1: str = "Item", col2: str = "Count", color: str = "cyan") -> Table:
    t = Table(title=title, box=box.SIMPLE_HEAVY, title_style=f"bold {color}",
              show_edge=False, padding=(0, 1))
    t.add_column(col1, style="white", no_wrap=True)
    t.add_column(col2, style=color, justify="right")
    t.add_column("Bar", no_wrap=True)
    total = sum(counter.values()) or 1
    for item, cnt in counter.most_common(top):
        pct = cnt / total
        bar = "█" * int(pct * 20)
        t.add_row(str(item), str(cnt), f"[dim]{bar}[/dim] {pct:.1%}")
    return t

def display_results(stats: TrafficStats):
    duration = ""
    if stats.start_time and stats.end_time:
        delta = (stats.end_time - stats.start_time).total_seconds()
        duration = f"{delta:.1f}s"

    avg_size = (sum(stats.packet_sizes) / len(stats.packet_sizes)) if stats.packet_sizes else 0
    max_size = max(stats.packet_sizes, default=0)

    console.print()
    console.rule("[bold green]NetScope — Traffic Analysis Report[/bold green]")
    console.print()

    # Summary panel
    summary_lines = [
        f"[bold]Source:[/bold]            {stats.source}",
        f"[bold]Total Packets/Req:[/bold] {stats.total_packets:,}",
        f"[bold]Total Bytes:[/bold]       {fmt_bytes(stats.total_bytes)}",
        f"[bold]Avg Packet Size:[/bold]   {avg_size:.1f} B",
        f"[bold]Max Packet Size:[/bold]   {max_size:,} B",
        f"[bold]Duration:[/bold]          {duration or 'N/A'}",
        f"[bold]Start:[/bold]             {stats.start_time or 'N/A'}",
        f"[bold]End:[/bold]               {stats.end_time or 'N/A'}",
    ]
    console.print(Panel("\n".join(summary_lines), title="[bold]Summary[/bold]",
                        border_style="green", padding=(1, 2)))
    console.print()

    # Protocol breakdown
    if stats.protocols:
        console.print(top_table("Protocol Distribution", stats.protocols, col1="Protocol", color="blue"))
        console.print()

    # Top IPs
    tables = []
    if stats.src_ips:
        tables.append(top_table("Top Source IPs", stats.src_ips, col1="IP", color="magenta"))
    if stats.dst_ips:
        tables.append(top_table("Top Destination IPs", stats.dst_ips, col1="IP", color="yellow"))
    if tables:
        console.print(Columns(tables, equal=True, expand=True))
        console.print()

    # Ports
    if stats.src_ports or stats.dst_ports:
        port_tables = []
        if stats.dst_ports:
            port_tables.append(top_table("Top Destination Ports", stats.dst_ports,
                                          col1="Port", color="cyan"))
        if stats.src_ports:
            port_tables.append(top_table("Top Source Ports", stats.src_ports,
                                          col1="Port", color="green"))
        console.print(Columns(port_tables, equal=True, expand=True))
        console.print()

    # TCP flags
    if stats.flags:
        console.print(top_table("TCP Flags", stats.flags, col1="Flag", color="red"))
        console.print()

    # DNS
    if stats.dns_queries:
        console.print(top_table("Top DNS Queries", stats.dns_queries,
                                col1="Domain", top=15, color="cyan"))
        console.print()

    # HTTP-specific
    if stats.http_methods:
        http_tables = [
            top_table("HTTP Methods", stats.http_methods, col1="Method", color="green"),
            top_table("Status Codes", stats.status_codes, col1="Code", color="yellow"),
        ]
        console.print(Columns(http_tables, equal=True, expand=True))
        console.print()

    if stats.user_agents:
        console.print(top_table("User Agents", stats.user_agents, col1="Agent", color="magenta"))
        console.print()

    console.rule("[dim]End of Report[/dim]")


# ── HTML Report ───────────────────────────────────────────────────────────────

def build_html_report(stats: TrafficStats, out_path: str):
    """Generate a self-contained HTML report with Chart.js visualizations."""

    def counter_json(c: Counter, top: int = 10) -> str:
        items = c.most_common(top)
        labels = json.dumps([str(k) for k, _ in items])
        values = json.dumps([v for _, v in items])
        return labels, values

    proto_l, proto_v = counter_json(stats.protocols)
    srcip_l, srcip_v = counter_json(stats.src_ips)
    dstport_l, dstport_v = counter_json(stats.dst_ports)
    method_l, method_v = counter_json(stats.http_methods) if stats.http_methods else ('[]', '[]')
    status_l, status_v = counter_json(stats.status_codes) if stats.status_codes else ('[]', '[]')
    ua_l, ua_v = counter_json(stats.user_agents) if stats.user_agents else ('[]', '[]')

    duration = ""
    if stats.start_time and stats.end_time:
        delta = (stats.end_time - stats.start_time).total_seconds()
        duration = f"{delta:.1f}s"

    avg_size = (sum(stats.packet_sizes) / len(stats.packet_sizes)) if stats.packet_sizes else 0

    PALETTE = ["#6366f1","#06b6d4","#10b981","#f59e0b","#ef4444",
               "#8b5cf6","#ec4899","#14b8a6","#f97316","#84cc16"]

    def chart_block(chart_id: str, title: str, labels: str, values: str,
                    kind: str = "bar") -> str:
        if labels == "[]":
            return ""
        colors = json.dumps(PALETTE[:len(json.loads(labels))])
        return f"""
        <div class="card">
          <h3>{title}</h3>
          <canvas id="{chart_id}"></canvas>
        </div>
        <script>
          new Chart(document.getElementById('{chart_id}'), {{
            type: '{kind}',
            data: {{
              labels: {labels},
              datasets: [{{ data: {values}, backgroundColor: {colors},
                borderColor: {colors}, borderWidth: 1 }}]
            }},
            options: {{
              responsive: true,
              plugins: {{ legend: {{ display: {'true' if kind == 'doughnut' else 'false'} }} }},
              scales: {'{}' if kind == 'doughnut' else '{"x": {"ticks": {"color": "#cbd5e1"}}, "y": {"ticks": {"color": "#cbd5e1"}}}'}
            }}
          }});
        </script>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetScope Report — {Path(stats.source).name}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif;
          padding: 2rem; }}
  h1 {{ font-size: 1.8rem; color: #6366f1; margin-bottom: .25rem; }}
  h2 {{ font-size: 1rem; color: #94a3b8; font-weight: normal; margin-bottom: 2rem; }}
  h3 {{ font-size: .95rem; color: #94a3b8; margin-bottom: 1rem; text-transform: uppercase;
        letter-spacing: .05em; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                  gap: 1rem; margin-bottom: 2rem; }}
  .stat {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px;
           padding: 1.25rem; text-align: center; }}
  .stat .val {{ font-size: 1.6rem; font-weight: 700; color: #6366f1; }}
  .stat .lbl {{ font-size: .78rem; color: #64748b; margin-top: .25rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
           gap: 1.5rem; }}
  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px;
           padding: 1.5rem; }}
  footer {{ margin-top: 3rem; text-align: center; color: #475569; font-size: .8rem; }}
</style>
</head>
<body>
<h1>🔍 NetScope — Traffic Analysis Report</h1>
<h2>Source: {stats.source}</h2>

<div class="stats-grid">
  <div class="stat"><div class="val">{stats.total_packets:,}</div><div class="lbl">Packets / Requests</div></div>
  <div class="stat"><div class="val">{fmt_bytes(stats.total_bytes)}</div><div class="lbl">Total Data</div></div>
  <div class="stat"><div class="val">{avg_size:.0f} B</div><div class="lbl">Avg Packet Size</div></div>
  <div class="stat"><div class="val">{len(stats.src_ips):,}</div><div class="lbl">Unique Source IPs</div></div>
  <div class="stat"><div class="val">{duration or 'N/A'}</div><div class="lbl">Duration</div></div>
  <div class="stat"><div class="val">{len(stats.protocols)}</div><div class="lbl">Protocols Seen</div></div>
</div>

<div class="grid">
  {chart_block("proto", "Protocol Distribution", proto_l, proto_v, "doughnut")}
  {chart_block("srcip", "Top Source IPs", srcip_l, srcip_v)}
  {chart_block("dstport", "Top Destination Ports", dstport_l, dstport_v)}
  {chart_block("method", "HTTP Methods", method_l, method_v, "doughnut")}
  {chart_block("status", "HTTP Status Codes", status_l, status_v)}
  {chart_block("ua", "User Agent Families", ua_l, ua_v)}
</div>

<footer>Generated by NetScope on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
</body>
</html>"""

    Path(out_path).write_text(html)
    console.print(f"\n[green]✓ HTML report saved:[/green] {out_path}")


# ── Sample data generator ─────────────────────────────────────────────────────

def generate_sample_log(outfile: str, n: int = 500):
    """Generate a sample Apache access log for demo purposes."""
    import random
    ips = ["192.168.1." + str(i) for i in range(1, 20)] + \
          ["10.0.0." + str(i) for i in range(1, 10)] + \
          ["203.0.113.5", "198.51.100.42", "45.33.32.156", "8.8.8.8"]
    methods = ["GET"] * 8 + ["POST"] * 3 + ["PUT", "DELETE", "HEAD"]
    url_paths = ["/", "/index.html", "/api/users", "/api/data", "/login",
                 "/static/app.js", "/static/style.css", "/favicon.ico",
                 "/robots.txt", "/sitemap.xml", "/api/metrics", "/health"]
    statuses = ["200"] * 10 + ["304"] * 3 + ["404"] * 2 + ["500", "301", "403", "401"]
    agents = [
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "curl/7.88.1",
        "python-requests/2.28.0",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (Macintosh) AppleWebKit/605.1 Safari/605.1",
    ]
    lines = []
    ts = datetime(2024, 6, 1, 0, 0, 0)
    from datetime import timedelta
    for _ in range(n):
        ip = random.choice(ips)
        method = random.choice(methods)
        path = random.choice(url_paths)
        status = random.choice(statuses)
        size = random.randint(200, 50000) if status == "200" else random.randint(0, 500)
        agent = random.choice(agents)
        ts += timedelta(seconds=random.randint(1, 120))
        ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"')
    Path(outfile).write_text("\n".join(lines))
    console.print(f"[green]✓ Sample log generated:[/green] {outfile} ({n} lines)")


# ── Wireshark / tshark Integration ───────────────────────────────────────────

WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 27017: "MongoDB",
}

def list_interfaces() -> list[dict]:
    """Return list of interfaces from tshark -D."""
    result = subprocess.run(
        ["tshark", "-D"], capture_output=True, text=True
    )
    ifaces = []
    for line in result.stdout.splitlines():
        m = re.match(r"(\d+)\.\s+(\S+)(?:\s+\((.+)\))?", line)
        if m:
            ifaces.append({"idx": m.group(1), "name": m.group(2),
                           "desc": m.group(3) or ""})
    return ifaces


def capture_with_tshark(interface: str, duration: int, output_pcap: str,
                         capture_filter: str = "") -> bool:
    """Run tshark capture and save to pcap. Returns True on success."""
    cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}",
           "-w", output_pcap, "-q"]
    if capture_filter:
        cmd += ["-f", capture_filter]

    console.print(f"\n[cyan]Starting capture[/cyan] on [bold]{interface}[/bold] "
                  f"for [bold]{duration}s[/bold]…")
    if capture_filter:
        console.print(f"[dim]Filter:[/dim] {capture_filter}")
    console.print("[dim]Press Ctrl+C to stop early.[/dim]\n")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
        if proc.returncode not in (0, 1):   # tshark exits 1 on Ctrl+C — fine
            console.print(f"[red]tshark error:[/red] {proc.stderr.strip()}")
            return False
        return Path(output_pcap).exists() and Path(output_pcap).stat().st_size > 0
    except subprocess.TimeoutExpired:
        console.print("[yellow]Capture timed out.[/yellow]")
        return False
    except KeyboardInterrupt:
        console.print("\n[yellow]Capture stopped by user.[/yellow]")
        return Path(output_pcap).exists()


def run_pipeline(interface: str, duration: int, html_out: str,
                 capture_filter: str = ""):
    """Full pipeline: capture → parse → display → HTML report."""

    if not shutil.which("tshark"):
        console.print("[red]tshark not found. Install Wireshark/tshark first.[/red]")
        sys.exit(1)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        pcap_path = f.name

    ok = capture_with_tshark(interface, duration, pcap_path, capture_filter)
    if not ok:
        console.print("[red]Capture failed or produced no packets.[/red]")
        sys.exit(1)

    pkt_count = int(subprocess.run(
        ["tshark", "-r", pcap_path, "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True
    ).stdout.strip().split("\n")[-1] or "0")
    console.print(f"[green]✓ Captured {pkt_count} packets →[/green] {pcap_path}\n")

    stats = parse_pcap(pcap_path)

    # Annotate destination ports with service names
    annotated = Counter()
    for port, cnt in stats.dst_ports.items():
        label = WELL_KNOWN_PORTS.get(port, str(port))
        key = f"{port} ({label})" if label != str(port) else str(port)
        annotated[key] = cnt
    stats.dst_ports = annotated

    display_results(stats)
    build_html_report(stats, html_out)
    console.print(f"\n[bold green]Pipeline complete.[/bold green] "
                  f"Open [cyan]{html_out}[/cyan] in your browser.")
    return stats


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="netscope",
        description="NetScope — Network Traffic Analyzer (PCAP & web server logs)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # analyse
    a = sub.add_parser("analyse", help="Analyse an existing PCAP or log file")
    a.add_argument("file", help="Path to .pcap, .pcapng, or access log file")
    a.add_argument("--html", metavar="OUT", help="Save HTML report to this path")
    a.add_argument("--top", type=int, default=10, help="Top N items to show (default 10)")

    # capture
    c = sub.add_parser("capture", help="Capture live traffic via tshark then analyse")
    c.add_argument("-i", "--interface", default="any",
                   help="Network interface (default: any). Use 'list' to show all.")
    c.add_argument("-d", "--duration", type=int, default=30,
                   help="Capture duration in seconds (default: 30)")
    c.add_argument("-f", "--filter", dest="capture_filter", default="",
                   help="BPF capture filter, e.g. 'tcp port 80'")
    c.add_argument("--html", metavar="OUT", default="/tmp/netscope_report.html",
                   help="Output HTML report path (default: /tmp/netscope_report.html)")

    # interfaces
    sub.add_parser("interfaces", help="List available network interfaces")

    # demo
    sub.add_parser("demo", help="Generate a sample access log and analyse it")

    args = parser.parse_args()

    # ── demo ──
    if args.cmd == "demo":
        sample = "/tmp/sample_access.log"
        generate_sample_log(sample, 1000)
        stats = parse_log(sample)
        display_results(stats)
        report = "/tmp/netscope_report.html"
        build_html_report(stats, report)
        return

    # ── interfaces ──
    if args.cmd == "interfaces":
        ifaces = list_interfaces()
        t = Table(title="Available Interfaces", box=box.SIMPLE_HEAVY,
                  title_style="bold cyan", show_edge=False)
        t.add_column("Index", style="dim", justify="right")
        t.add_column("Name", style="bold white")
        t.add_column("Description", style="dim")
        for i in ifaces:
            t.add_row(i["idx"], i["name"], i["desc"])
        console.print(t)
        return

    # ── capture ──
    if args.cmd == "capture":
        if args.interface == "list":
            ifaces = list_interfaces()
            for i in ifaces:
                console.print(f"  [cyan]{i['idx']}[/cyan]. {i['name']}  [dim]{i['desc']}[/dim]")
            return
        run_pipeline(args.interface, args.duration, args.html, args.capture_filter)
        return

    # ── analyse ──
    path = args.file
    if not Path(path).exists():
        console.print(f"[red]File not found: {path}[/red]")
        sys.exit(1)

    ext = Path(path).suffix.lower()
    if ext in (".pcap", ".pcapng", ".cap"):
        stats = parse_pcap(path)
    else:
        stats = parse_log(path)

    display_results(stats)

    if args.html:
        build_html_report(stats, args.html)


if __name__ == "__main__":
    main()
