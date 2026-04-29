# 🔍 NetScope

A command-line network traffic analyzer that captures live packets via Wireshark (tshark), parses PCAP files and web server logs, and generates clean visual reports.

Built in Python.

---

## What it does

You run it, it captures traffic (or reads a file you already have), and spits out a breakdown of everything — which IPs are talking, what protocols, which ports, DNS queries being made, TCP flag patterns, HTTP status codes. Then it generates a self-contained HTML report you can share or keep.

```
python netscope.py capture -i eth0 -d 30 --html report.html
```

That's it. Capture 30 seconds of traffic on eth0, analyze it, save the report.

---

## Features

- **Live capture** — wraps tshark to capture packets directly from any interface
- **PCAP analysis** — feed it any `.pcap` or `.pcapng` file (e.g. from Wireshark)
- **Log parsing** — supports Apache and Nginx combined access log format
- **Protocol breakdown** — TCP, UDP, ICMP, and more
- **Top talkers** — src/dst IPs ranked by packet count
- **Port analysis** — destination ports with service name labels (443 → HTTPS, 53 → DNS, etc.)
- **TCP flags** — SYN, ACK, FIN, RST distribution
- **DNS queries** — what domains are being looked up
- **HTTP insights** — methods, status codes, user agent families (when parsing logs)
- **HTML report** — self-contained, shareable, Chart.js visualizations
- **Rich CLI output** — color-coded tables with inline bar charts, no walls of text

---

## Requirements

- Python 3.10+
- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) (Wireshark CLI)
- Python packages: `rich`

**Install tshark:**

```bash
# Ubuntu / Debian
sudo apt install tshark

# macOS
brew install wireshark

# Windows — install Wireshark from wireshark.org (includes tshark)
```

**Install Python dependencies:**

```bash
pip install rich
```

> Live capture requires root/sudo on Linux, or adding your user to the `wireshark` group:
> ```bash
> sudo usermod -aG wireshark $USER
> # then log out and back in
> ```

---

## Usage

### List available interfaces

```bash
python netscope.py interfaces
```

```
 Index   Name       Description
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     1   eth0
     2   any
     3   lo         Loopback
```

### Capture live traffic

```bash
# Capture 30 seconds on eth0
python netscope.py capture -i eth0 -d 30 --html report.html

# Only capture HTTP/HTTPS traffic
python netscope.py capture -i eth0 -d 60 -f "tcp port 80 or tcp port 443" --html report.html

# Capture on any interface for 2 minutes
python netscope.py capture -i any -d 120 --html report.html
```

### Analyze an existing PCAP

```bash
python netscope.py analyse capture.pcap --html report.html
python netscope.py analyse capture.pcapng --html report.html
```

### Analyze a web server access log

```bash
python netscope.py analyse /var/log/nginx/access.log --html report.html
python netscope.py analyse /var/log/apache2/access.log --html report.html
```

### Run the built-in demo

Generates a sample access log and analyzes it — good for testing without any setup.

```bash
python netscope.py demo
```

---

## Example output

```
────────────── NetScope — Traffic Analysis Report ──────────────

  Source:            capture.pcap
  Total Packets/Req: 4,821
  Total Bytes:       6.2 MB
  Avg Packet Size:   1,312 B
  Duration:          30.0s

             Protocol Distribution
 Protocol   Count   Bar
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 TCP         3,944   ████████████████ 81.8%
 UDP           721   ███ 14.9%
 ICMP          156   █ 3.2%

      Top Destination Ports
 Port              Count   Bar
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 443 (HTTPS)       2,201   ████████ 45.6%
 53 (DNS)            701   ██ 14.5%
 80 (HTTP)           312   █ 6.5%
 22 (SSH)            189   █ 3.9%
```

---

## Project structure

```
netscope/
├── netscope.py       # everything lives here — parser, analyzer, reporter, CLI
├── README.md
├── requirements.txt
└── .gitignore
```

Single-file by design. Easy to read, easy to audit, easy to drop onto any machine.

---

## Roadmap / ideas

- [ ] GeoIP lookup — map IPs to countries
- [ ] Anomaly detection — flag port scans, traffic spikes, unusual patterns
- [ ] Live dashboard — stream stats in real time instead of waiting for capture to finish
- [ ] JSON export — for piping into other tools

---

## License

MIT — do whatever you want with it.
