import random
import time
import json
import os
import asyncio
from datetime import datetime

EVE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "suricata_eve.json")

# Sources: Syslog, Suricata, Wazuh, Windows, Nginx
SOURCES = ["Syslog", "Suricata", "Wazuh", "Windows", "Nginx"]

NORMAL_LOGS = [
    # Nginx
    ("Nginx", "INFO", '192.168.1.{ip_last} - - [{timestamp}] "GET /static/css/main.css HTTP/1.1" 200 8124 "-" "Mozilla/5.0"'),
    ("Nginx", "INFO", '192.168.1.{ip_last} - - [{timestamp}] "GET /api/v1/health HTTP/1.1" 200 45 "-" "UptimeRobot/2.0"'),
    ("Nginx", "INFO", '192.168.1.{ip_last} - - [{timestamp}] "GET /index.html HTTP/1.1" 200 1204 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'),
    # Syslog
    ("Syslog", "INFO", "<30>Jul 05 16:53:54 host-pc CRON[812]: (root) CMD (   /usr/local/bin/backup.sh > /dev/null 2>&1)"),
    ("Syslog", "INFO", "<30>Jul 05 16:53:54 host-pc systemd[1]: Starting Session 42 of user local-user."),
    ("Syslog", "INFO", "<30>Jul 05 16:53:54 web-svr kernel: [12948.192348] EXT4-fs (sda1): re-mounted. Opts: errors=remount-ro"),
    # Windows
    ("Windows", "INFO", "INFO: EventID=4624 (An account was successfully logged on) SubjectUser=SYSTEM TargetUser=user.{id} Domain=WORKGROUP IP=192.168.1.{ip_last}"),
    ("Windows", "INFO", "INFO: EventID=4769 (A Kerberos service ticket was requested) TargetUser=user.{id} ServiceName=krbtgt ClientIP=192.168.1.{ip_last}"),
    # Wazuh
    ("Wazuh", "INFO", '{"event_type": "integrity_check", "file": "/etc/resolv.conf", "action": "checked", "message": "File integrity verified, no changes detected."}'),
    ("Wazuh", "INFO", '{"event_type": "process_start", "process": "systemd-resolved", "user": "systemd-resolve", "message": "Process started successfully."}')
]

ATTACK_SCENARIOS = [
    "ssh_brute_force",
    "port_scan",
    "malware_download",
    "privilege_elevation"
]

class MockLogGenerator:
    def __init__(self, callback_func, config: dict):
        self.callback_func = callback_func
        self.config = config
        self.interval = config.get("mock_generator", {}).get("interval_seconds", 1.5)
        self.running = False
        
        # Attack trackers to maintain multi-step events
        self.brute_force_ip = "192.168.5.110"
        self.port_scan_ip = "192.168.9.15"
        self.brute_force_counter = 0
        self.port_scan_counter = 0
        
        # Prepare eve.json
        if os.path.exists(EVE_FILE):
            try:
                os.remove(EVE_FILE)
            except Exception:
                pass
        with open(EVE_FILE, 'w') as f:
            f.write("")

    async def start(self):
        self.running = True
        print("Mock Log Generator Started!")
        while self.running:
            try:
                await self.generate_step()
            except Exception as e:
                print(f"Error in mock log generator: {e}")
            await asyncio.sleep(self.interval)

    def stop(self):
        self.running = False

    async def generate_step(self):
        # 80% chance of normal log, 20% chance of advancing/triggering an attack scenario
        roll = random.random()
        if roll < 0.8:
            await self.emit_normal_log()
        else:
            scenario = random.choice(ATTACK_SCENARIOS)
            if scenario == "ssh_brute_force":
                await self.emit_ssh_failed_login()
            elif scenario == "port_scan":
                await self.emit_port_scan_step()
            elif scenario == "malware_download":
                await self.emit_malware_alert()
            elif scenario == "privilege_elevation":
                await self.emit_privilege_elevation()

    async def emit_normal_log(self):
        source, level, template = random.choice(NORMAL_LOGS)
        timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0530")
        ip_last = random.randint(2, 254)
        user_id = random.randint(100, 999)
        
        message = template
        if "{" in template:
            try:
                json.loads(template)
            except Exception:
                message = template.format(timestamp=timestamp, ip_last=ip_last, id=user_id)
                
        await self.callback_func(message, source)

    async def emit_ssh_failed_login(self):
        # Simulate SSH Brute Force step.
        # We will emit 1 failed login log. If it runs multiple times, it will trigger the correlation alert.
        self.brute_force_counter += 1
        username = random.choice(["root", "admin", "ubnt", "support", "test"])
        
        # Linux auth syslog format
        message = f"<131>Jul 05 16:53:54 web-server sshd[28441]: Failed password for {username} from {self.brute_force_ip} port {random.randint(30000, 65000)} ssh2"
        await self.callback_func(message, "Syslog")
        
        # Reset brute force IP occasionally so it scans from a new one later
        if self.brute_force_counter >= 6:
            self.brute_force_counter = 0
            self.brute_force_ip = f"192.168.5.{random.randint(100, 200)}"

    async def emit_port_scan_step(self):
        # Simulate port scan step
        # Emit a single connection attempt to a different port each time.
        self.port_scan_counter += 1
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]
        port = ports[self.port_scan_counter % len(ports)]
        
        message = f"Firewall: connection_attempt from {self.port_scan_ip} to 192.168.1.10 port={port}"
        await self.callback_func(message, "Syslog")
        
        if self.port_scan_counter >= 12:
            self.port_scan_counter = 0
            self.port_scan_ip = f"192.168.9.{random.randint(10, 99)}"

    async def emit_malware_alert(self):
        # Malware threat is written to suricata_eve.json file to trigger the file tailer!
        malware_sigs = [
            ("ET TROJAN DNS Query to suspicious .xyz Domain (Coinminer malware communication)", "A Network Trojan was Detected", 1),
            ("ET EXPLOIT Apache Struts RCE Exploit Attempt (CVE-2017-5638)", "Attempted Administrator Privilege Gain", 1),
            ("ET MALWARE Downloader active - Cobalt Strike Beacon connection", "Adware or Command and Control Activity", 1),
            ("ET SHELLCODE Common Reverse Shell payload detected", "Executable Code Detection", 1)
        ]
        sig, cat, sev = random.choice(malware_sigs)
        src_ip = f"192.168.1.{random.randint(50, 150)}"
        dst_ip = f"185.220.101.{random.randint(2, 254)}"
        
        alert_json = {
            "timestamp": datetime.now().isoformat() + "+05:30",
            "event_type": "alert",
            "src_ip": src_ip,
            "src_port": random.randint(1024, 65535),
            "dest_ip": dst_ip,
            "dest_port": random.choice([80, 443, 8080, 4444]),
            "proto": "TCP",
            "alert": {
                "signature": sig,
                "category": cat,
                "severity": sev
            }
        }
        
        # Write to suricata_eve.json
        try:
            with open(EVE_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(alert_json) + "\n")
        except Exception as e:
            print(f"Error writing to eve.json: {e}")

    async def emit_privilege_elevation(self):
        user = random.choice(["sysadmin", "dev_user", "operator", "dba_service"])
        command = random.choice(["/bin/bash", "/usr/bin/apt-get upgrade", "systemctl stop firewalld", "rm -rf /var/log"])
        
        elev_type = random.choice(["sudo", "runas"])
        if elev_type == "sudo":
            message = f"<133>Jul 05 16:53:54 database-svr sudo:      {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND={command}"
            await self.callback_func(message, "Syslog")
        else:
            message = f"INFO: Windows EventID=4648 (RunAs elevation attempted) User={user} elevated privileges to Administrator to run {command}"
            await self.callback_func(message, "Windows")
