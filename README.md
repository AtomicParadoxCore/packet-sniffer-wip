# Automated Packet Sniffer & Anomaly Detector

A lightweight, real-time packet sniffer built in Python with Scapy. It monitors live network traffic across TCP and UDP, logs it, and tracks network velocity (packets per second) — the first step toward an anomaly/DoS detector.

## Goal

Build a Python tool that sits on a network, intercepts raw data traffic, decodes it, and (eventually) sounds an alarm if someone is trying to flood the system — like a DoS attack or DNS spoofing.

Core concepts I set out to learn: the OSI Model (Layers 2, 3, and 4), TCP vs UDP, DNS mechanics, and network data structures.

## Current State

**Working:**
- Real-time packet capture using Scapy's `AsyncSniffer` (non-blocking, runs alongside a live loop)
- Parses IP, TCP, and UDP layers out of raw traffic
- Tracks packets-per-second (PPS) in real time
- Tracks top talking IPs and most-targeted ports
- Logs every packet to `network_log.txt` (append mode, so nothing gets overwritten)
- Prints a full session summary (duration, average PPS, top talkers, top ports) on clean shutdown

**Not built yet:**
- The actual anomaly/DoS alarm — right now the tool tracks PPS and top talkers but doesn't flag or alert on abnormal traffic yet
- DNS spoofing detection
- Any use of DNS mechanics (planned, not implemented)

This is a work in progress, not a finished tool.

## How It Works

`sniffer.py` runs an `AsyncSniffer` in the background while the main thread stays free to catch `Ctrl+C` cleanly. Every IP packet is counted the moment it's confirmed as IP (before any TCP/UDP-specific logic), so nothing is missed. PPS is calculated using a `None`-flag pattern on `start_time`, so Scapy's few seconds of library-loading time at boot never get counted as part of the traffic timing — the stopwatch only starts on the first real packet. See [`none-as-stopwatch-flag.docx`](./none-as-stopwatch-flag.docx) for the full breakdown of that pattern.

On shutdown, it prints and logs a summary: total packets captured, session duration, average PPS, top 5 talking IPs, and top 5 targeted ports.

## Bugs I Hit and Fixed

Full write-ups are in [`issues_resolved.txt`](./issues_resolved.txt), including:
- A stale-count bug where PPS showed `0` for the first 15-20 packets (counter was incrementing *after* the PPS math ran)
- A race condition on the NIC when packets arrive near-simultaneously
- Why `Ctrl+C` wasn't triggering my shutdown/summary code on Windows (SIGINT kill-switch behavior)

## Notes

Background notes on the concepts behind this project (OSI model, TCP vs UDP, promiscuous mode, IP address types) are in [`osi-model-and-tcp-udp-notes.txt`](./osi-model-and-tcp-udp-notes.txt).

## Setup

```bash
pip install -r requirements.txt
```

Scapy needs elevated privileges to open raw sockets and enable promiscuous mode:

```bash
# Windows (as Administrator)
python sniffer.py

# Linux/Mac
sudo python3 sniffer.py
```

Press `Ctrl+C` to stop — this prints a session summary and appends it to `network_log.txt`.

## Next Steps

- Add threshold-based flood/DoS detection using the existing PPS tracking
- Add basic DNS spoofing detection
- Add configurable alert thresholds instead of hardcoded values
