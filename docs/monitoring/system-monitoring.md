# System Monitoring

## Overview

The Inovix monitoring foundation collects basic system activity and
converts it into standardized events.

The collectors only collect factual system information.

They do not perform:

- Malware detection
- Threat intelligence lookup
- IOC matching
- Risk scoring
- Verdict generation
- Process termination
- Network blocking

Security analysis is handled separately by the Security Engine.

## Architecture

System
   |
   |
Process ---> Event Collectors ---> Security Engine
   |
   |
Network

## Collectors

### System Collector

The SystemCollector collects:

- CPU usage
- Memory usage
- Disk usage
- System uptime
- Hostname
- Operating system

Example event:

{
    "event_type": "system",
    "source": "system_monitor",
    "timestamp": "...",
    "data": {
        "cpu_percent": 25.0,
        "memory_percent": 48.0,
        "disk_percent": 62.0,
        "uptime_seconds": 12000,
        "hostname": "DESKTOP",
        "os": "Windows"
    }
}

### Process Collector

The ProcessCollector collects:

- Process ID
- Process name
- Username when available
- CPU usage
- Memory usage
- Parent process ID
- Process creation time

Each running process is converted into a standardized monitoring event.

Processes that disappear during collection or cannot be accessed due to
permission restrictions are skipped.

The collector does not classify processes as safe or malicious.

### Network Collector

The NetworkCollector collects:

- Local address
- Remote address
- Connection status
- Process ID when available

Each active network connection is converted into a standardized event.

If network connection information cannot be accessed, the collector
returns an empty result instead of crashing the application.

## Standard Event Format

All collectors use the MonitoringEvent model.

Every event contains:

{
    "event_type": "...",
    "source": "...",
    "timestamp": "...",
    "data": {
        ...
    }
}

Fields:

- event_type identifies the type of system activity.
- source identifies the collector that produced the event.
- timestamp records when the event was collected.
- data contains collector-specific factual information.

## Collector Interface

All collectors follow a common interface.

Collector
    |
    |-- collect()
    |-- start()
    |-- stop()
    |-- status()

The collectors are safe to call repeatedly.

They do not run permanent uncontrolled loops.

This allows future integration with:

- Background workers
- Scheduled polling
- Queues
- Terminal dashboard updates

## Collection Frequency

The current monitoring foundation does not enforce a permanent
collection loop.

Collectors can be called repeatedly by a future monitoring scheduler.

The collection interval should remain configurable to avoid unnecessary
CPU and memory usage.

## Error Handling

System monitoring can encounter temporary errors.

Examples include:

- Process exits during inspection
- Permission denied
- Network connection disappears
- Network connection information unavailable

Expected errors are handled gracefully.

Individual unavailable processes are skipped.

If an entire collection operation cannot access system information,
the collector returns an empty result where appropriate instead of
crashing Inovix.

## Privacy

The monitoring foundation only collects information required for
basic system security telemetry.

It does not collect:

- Passwords
- Browser history contents
- Personal document contents
- Message contents
- Keystrokes
- Screenshots
- Clipboard contents

## Testing

Run collector tests:

python -m pytest security_engine\tests\test_collectors.py -v

Run syntax validation:

python -m py_compile security_engine\monitoring_events.py
python -m py_compile security_engine\collectors\base.py
python -m py_compile security_engine\collectors\system.py
python -m py_compile security_engine\collectors\process.py
python -m py_compile security_engine\collectors\network.py

The collectors are designed to provide standardized events for future
integration with the Security Engine, database, and terminal dashboard.