#!/var/ossec/framework/python/bin/python3
"""
Wazuh -> MISP IOC lookup integration.

Wazuh's integrator calls this script for every alert in the configured groups:
    custom-misp.py <alert_file> <api_key> <hook_url>
The indicator in the alert (file hash, destination IP, DNS name) is looked up in MISP.
On a hit, an enriched event is written back to Wazuh's queue, where rule 100622 raises
a high-severity alert. The MISP URL and API key come from ossec.conf, never from this file.

Optional settings: custom-misp.json next to this script, e.g. {"verify_tls": false, "timeout": 10}
"""
import ipaddress
import json
import os
import re
import socket
import sys

import requests

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
WAZUH_HOME = os.path.dirname(SCRIPT_DIR)
QUEUE_SOCKET = os.environ.get("WAZUH_QUEUE_SOCKET", os.path.join(WAZUH_HOME, "queue", "sockets", "queue"))
SHA256 = re.compile(r"(?:SHA256=)?\b([A-Fa-f0-9]{64})\b")

# Sysmon event groups -> (field holding the IOC, kind of IOC)
WINDOWS_FIELDS = {
    "sysmon_event1": ("hashes", "hash"),        # process creation
    "sysmon_event3": ("destinationIp", "ip"),   # network connection
    "sysmon_event6": ("hashes", "hash"),        # driver loaded
    "sysmon_event7": ("hashes", "hash"),        # image (DLL) loaded
    "sysmon_event_15": ("hash", "hash"),        # file stream created
    "sysmon_event_22": ("queryName", "domain"), # DNS query
    "sysmon_event_23": ("hashes", "hash"),      # file delete archived
    "sysmon_event_24": ("hashes", "hash"),      # clipboard capture
    "sysmon_event_25": ("hashes", "hash"),      # process tampering
}


def load_settings():
    settings = {"verify_tls": True, "timeout": 10}
    path = os.path.join(SCRIPT_DIR, "custom-misp.json")
    if os.path.exists(path):
        with open(path) as f:
            settings.update(json.load(f))
    return settings


def extract_ioc(alert):
    """Return (value, kind) for the indicator in this alert, or (None, None)."""
    groups = alert.get("rule", {}).get("groups", [])
    data = alert.get("data", {})

    if "syscheck" in alert:  # Wazuh file integrity monitoring: new or changed file
        value = alert["syscheck"].get("sha256_after")
        return (value, "hash") if value else (None, None)

    eventdata = data.get("win", {}).get("eventdata") or data.get("eventdata") or {}
    for group in groups:
        if group not in WINDOWS_FIELDS:
            continue
        field, kind = WINDOWS_FIELDS[group]
        # Sysmon for Linux capitalises some field names
        raw = eventdata.get(field) or eventdata.get(field[0].upper() + field[1:])
        if not raw:
            return None, None
        if kind == "hash":
            m = SHA256.search(raw)
            return (m.group(1).lower(), kind) if m else (None, None)
        if kind == "ip":
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError:
                return None, None
            # private, loopback and link-local addresses can't be threat intel hits
            return (str(ip), kind) if ip.is_global else (None, None)
        return raw.strip().rstrip(".").lower(), kind
    return None, None


def query_misp(base_url, api_key, value, settings):
    r = requests.post(
        base_url.rstrip("/") + "/attributes/restSearch",
        headers={"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"},
        json={"value": value, "to_ids": True, "returnFormat": "json", "limit": 5},
        timeout=settings["timeout"],
        verify=settings["verify_tls"],
    )
    r.raise_for_status()
    return r.json().get("response", {}).get("Attribute", [])


def send_event(message, agent):
    if not agent or agent.get("id") == "000":
        line = "1:misp:{0}".format(json.dumps(message))
    else:
        line = "1:[{0}] ({1}) {2}->misp:{3}".format(
            agent["id"], agent.get("name", ""), agent.get("ip", "any"), json.dumps(message))
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.connect(QUEUE_SOCKET)
        sock.send(line.encode())
    finally:
        sock.close()


def main(argv):
    if len(argv) < 4:
        sys.stderr.write("usage: custom-misp.py <alert_file> <api_key> <misp_url>\n")
        return 1
    alert_file, api_key, base_url = argv[1], argv[2], argv[3]
    with open(alert_file) as f:
        alert = json.load(f)

    value, kind = extract_ioc(alert)
    if not value:
        return 0  # nothing to look up in this alert

    settings = load_settings()
    out = {"integration": "misp", "misp": {}}
    try:
        hits = query_misp(base_url, api_key, value, settings)
    except requests.RequestException as e:
        out["misp"]["error"] = "MISP API request failed: {0}".format(type(e).__name__)
        send_event(out, alert.get("agent"))
        return 0
    if not hits:
        return 0

    hit = hits[0]
    out["misp"] = {
        "event_id": hit.get("event_id"),
        "category": hit.get("category"),
        "value": hit.get("value"),
        "type": hit.get("type"),
        "ioc_kind": kind,
        "hits": len(hits),
        "source": {"rule_id": alert.get("rule", {}).get("id"), "description": alert.get("rule", {}).get("description")},
    }
    send_event(out, alert.get("agent"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
