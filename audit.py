#!/usr/bin/env python3
"""Read-only local security configuration audit for learning purposes."""
import argparse
import json
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

COMMON_LOCAL_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "Alternate HTTP / development server",
}

def run_read_only(command, timeout=3):
    """Run a read-only system command; return output or None."""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
        if result.returncode == 0:
            return (result.stdout + "\n" + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None

def firewall_check(system):
    if system == "Windows":
        output = run_read_only(
            ["netsh", "advfirewall", "show", "allprofiles", "state"]
        )
        if output:
            lowered = output.lower()
            if "state" in lowered and "on" in lowered:
                return {"status": "enabled", "evidence": "Windows firewall reports one or more profiles On"}
            if "state" in lowered and "off" in lowered:
                return {"status": "review", "evidence": "Windows firewall output includes an Off state; verify each profile"}
        return {"status": "unknown", "evidence": "Could not reliably parse netsh output"}
    if system == "Linux":
        output = run_read_only(["ufw", "status"])
        if output:
            first_line = output.lower().splitlines()[0] if output.splitlines() else ""
            if "active" in first_line:
                return {"status": "enabled", "evidence": "UFW reports Status: active"}
            if "inactive" in first_line:
                return {"status": "review", "evidence": "UFW reports Status: inactive; another firewall may still be active"}
        return {"status": "unknown", "evidence": "UFW unavailable or status not recognized; check your firewall tool manually"}
    if system == "Darwin":
        output = run_read_only(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        if output:
            lowered = output.lower()
            if "enabled" in lowered:
                return {"status": "enabled", "evidence": output}
            if "disabled" in lowered:
                return {"status": "review", "evidence": output}
        return {"status": "unknown", "evidence": "Could not read macOS application firewall state"}
    return {"status": "unknown", "evidence": "Unsupported operating system"}

def check_loopback_ports():
    results = []
    for port, service in COMMON_LOCAL_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.25)
        try:
            is_open = sock.connect_ex(("127.0.0.1", port)) == 0
        except OSError:
            is_open = False
        finally:
            sock.close()
        results.append({
            "port": port,
            "service_hint": service,
            "status": "open_on_loopback" if is_open else "not_detected",
            "note": "Review whether this local service is needed" if is_open else "No TCP listener detected on loopback",
        })
    return results

def main():
    parser = argparse.ArgumentParser(description="Read-only local security configuration audit")
    parser.add_argument("--output", default="secureconfig-report.json", help="JSON report path")
    args = parser.parse_args()

    system = platform.system()
    report = {
        "tool": "SecureConfig",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Local host only; loopback TCP checks use 127.0.0.1",
        "platform": {
            "system": system,
            "release": platform.release(),
            "python_version": platform.python_version(),
        },
        "checks": {
            "firewall": firewall_check(system),
            "loopback_ports": check_loopback_ports(),
        },
        "limitations": [
            "This is a small learning tool, not a full security scanner.",
            "Only a short list of TCP ports on 127.0.0.1 is checked.",
            "Firewall parsing and availability vary by operating system.",
            "A result of unknown means the check could not verify the state.",
        ],
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Audit complete. Report saved to: {output_path}")
    print(f"Firewall status: {report['checks']['firewall']['status']}")
    open_ports = [str(item["port"]) for item in report["checks"]["loopback_ports"]
                  if item["status"] == "open_on_loopback"]
    print("Detected loopback ports: " + (", ".join(open_ports) if open_ports else "none from the tested list"))
    print("Review the JSON report before sharing it.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
