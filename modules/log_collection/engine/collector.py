from .storage import save_parsed_log
import asyncio
import re
import os
import json
import uuid
from datetime import datetime

# Regex for IPv4 addresses
IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# Regex for finding port numbers (e.g., port 22, port=80, etc.)
PORT_REGEX = re.compile(r'\b(?:port\s*[:=]?\s*|port\s+)([0-9]+)\b', re.IGNORECASE)


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, callback_func=None):
        self.callback_func = callback_func

    def datagram_received(self, data, addr):
        try:
            message = data.decode("utf-8", errors="ignore")
            source = f"Syslog:{addr[0]}"

            # Automatically normalize and save
            asyncio.create_task(process_log(message, source))

            # Optional callback
            if self.callback_func:
                asyncio.create_task(
                    self.callback_func(message, source)
                )

        except Exception as e:
            print(f"Error parsing syslog datagram: {e}")


async def tail_file(file_path: str, callback_func=None):
    """
    Tails a file asynchronously.
    Every new line is normalized and stored automatically.
    """

    print(f"Starting file tailer for: {file_path}")

    if not os.path.exists(file_path):
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)

        with open(file_path, "w") as f:
            f.write("")

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:

        # Go to end of file
        f.seek(0, 2)

        while True:

            line = f.readline()

            if not line:
                await asyncio.sleep(0.5)
                continue

            line_str = line.strip()

            if not line_str:
                continue

            source = f"File:{os.path.basename(file_path)}"

            # Automatically normalize and store
            asyncio.create_task(
                process_log(line_str, source)
            )

            # Optional callback
            if callback_func:
                asyncio.create_task(
                    callback_func(line_str, source)
                )


def normalize_log(raw_msg: str, source: str) -> dict:
    print("\n==============================")
    print("RAW MESSAGE RECEIVED:")
    print(raw_msg)
    print("==============================")

    timestamp = datetime.now().isoformat()
    """
    Normalizes log from any source
    (Syslog, Suricata, Wazuh, JSON, etc.)
    into a standard format.
    """

    timestamp = datetime.now().isoformat()
    log_id = str(uuid.uuid4())
    level = "INFO"
    parsed_data = {}
    message = raw_msg
    user_match = None   
    # -----------------------------
    # JSON LOGS
    # -----------------------------
    try:

        data = json.loads(raw_msg)

        if isinstance(data, dict):

            if "timestamp" in data:
                timestamp = data["timestamp"]

            elif "time" in data:
                timestamp = data["time"]

            if "level" in data:

                level = str(data["level"]).upper()

            elif "severity" in data:

                sev = str(data["severity"]).upper()

                if sev in ["1", "CRITICAL", "HIGH"]:
                    level = "CRITICAL"

                elif sev in ["2", "ERROR", "MEDIUM"]:
                    level = "ERROR"

                elif sev in ["3", "WARNING", "LOW"]:
                    level = "WARNING"

                else:
                    level = "INFO"

            if "message" in data:

                message = data["message"]

            elif (
                "alert" in data
                and isinstance(data["alert"], dict)
                and "signature" in data["alert"]
            ):

                message = f"Suricata Alert: {data['alert']['signature']}"

                level = (
                    "CRITICAL"
                    if data["alert"].get("severity", 3) <= 1
                    else "WARNING"
                )

                parsed_data["signature"] = data["alert"]["signature"]

                parsed_data["category"] = data["alert"].get(
                    "category",
                    "Generic"
                )

            for key in [
                "src_ip",
                "dest_ip",
                "src_port",
                "dest_port",
                "proto",
                "event_type",
                "user",
                "username",
                "action",
                "hostname"
            ]:

                if key in data:

                    std_key = key

                    if key == "dest_ip":
                        std_key = "dst_ip"

                    elif key == "dest_port":
                        std_key = "dst_port"

                    parsed_data[std_key] = data[key]

            parsed_data.update({
                k: v
                for k, v in data.items()
                if k not in [
                    "timestamp",
                    "time",
                    "level",
                    "severity",
                    "message"
                ]
                and not isinstance(v, (dict, list))
            })
        # ---------------------------------
# Parse the message inside JSON logs
# ---------------------------------

        ips = IP_REGEX.findall(message)

        if len(ips) >= 1:
           parsed_data["src_ip"] = ips[0]

        if len(ips) >= 2:
           parsed_data["dst_ip"] = ips[1]

        ports = PORT_REGEX.findall(message)

        if len(ports) >= 1:
           parsed_data["src_port"] = int(ports[0])

        if len(ports) >= 2:
           parsed_data["dst_port"] = int(ports[1])

        msg_lower = message.lower()

# SSH Failed Login
        if (
            "failed" in msg_lower
            or "failure" in msg_lower
            or "unauthorized" in msg_lower
            or "denied" in msg_lower
        ):

         if (
             "login" in msg_lower
             or "auth" in msg_lower
             or "password" in msg_lower
    ):

             level = "WARNING"
             parsed_data["event_type"] = "login_failed"
             parsed_data["action"] = "login_failed"

# SSH Success
        elif (
              "accepted" in msg_lower
              or "successful" in msg_lower
):

         if (
             "login" in msg_lower
              or "auth" in msg_lower
              or "password" in msg_lower
    ):

            level = "INFO"
            parsed_data["event_type"] = "login_success"
            parsed_data["action"] = "login_success"

# Windows Events

        if "eventid=4625" in msg_lower:

            parsed_data["event_type"] = "login_failed"
            parsed_data["action"] = "login_failed"

        elif "eventid=4648" in msg_lower:

              parsed_data["event_type"] = "login_success"
              parsed_data["action"] = "login_success"

        elif "eventid=4648" in msg_lower:

               parsed_data["event_type"] = "privilege_escalation"
               parsed_data["action"] = "privilege_escalation"

# Firewall

        if "connection_attempt" in msg_lower:

            parsed_data["event_type"] = "connection_attempt"
            parsed_data["action"] = "connection_attempt"

# Username

        user_match = re.search(
              r"\b(?:user|username|for)\s+([a-zA-Z0-9_\-\.]+)\b",
              message,
              re.IGNORECASE
)

        if user_match:

             parsed_data["user"] = user_match.group(1)

    except json.JSONDecodeError:

        # -----------------------------
        # TEXT LOGS
        # -----------------------------

        pri_match = re.match(r"^<(\d+)>(.*)", raw_msg)

        if pri_match:

            pri = int(pri_match.group(1))

            message = pri_match.group(2).strip()

            syslog_severity = pri & 7

            if syslog_severity <= 2:
                level = "CRITICAL"

            elif syslog_severity == 3:
                level = "ERROR"

            elif syslog_severity == 4:
                level = "WARNING"

            else:
                level = "INFO"

        ips = IP_REGEX.findall(message)

        if len(ips) >= 1:
            parsed_data["src_ip"] = ips[0]

        if len(ips) >= 2:
            parsed_data["dst_ip"] = ips[1]

        ports = PORT_REGEX.findall(message)

        if len(ports) >= 1:
            parsed_data["src_port"] = int(ports[0])

        if len(ports) >= 2:
            parsed_data["dst_port"] = int(ports[1])

        msg_lower = message.lower()

        if (
            "failed" in msg_lower
            or "failure" in msg_lower
            or "unauthorized" in msg_lower
            or "denied" in msg_lower
):

            if "login" in msg_lower or "auth" in msg_lower or "password" in msg_lower:

                level = "WARNING"
                parsed_data["event_type"] = "login_failed"
                parsed_data["action"] = "login_failed"
        elif (
              "successful" in msg_lower
              or "accepted" in msg_lower
):

          if "login" in msg_lower or "auth" in msg_lower or "password" in msg_lower:

           level = "INFO"
           parsed_data["event_type"] = "login_success"
           parsed_data["action"] = "login_success"

        # -----------------------------
# ADD PROBLEM 3 HERE
# -----------------------------
        if "connection_attempt" in msg_lower:
            parsed_data["event_type"] = "connection_attempt"
            parsed_data["action"] = "connection_attempt"

# -----------------------------
# ADD PROBLEM 4 HERE
# -----------------------------
        if "eventid=4625" in msg_lower:
           parsed_data["event_type"] = "login_failed"
           parsed_data["action"] = "login_failed"

        elif "eventid=4624" in msg_lower:
             parsed_data["event_type"] = "login_success"
             parsed_data["action"] = "login_success"

        elif "eventid=4648" in msg_lower:
             parsed_data["event_type"] = "privilege_escalation"
             parsed_data["action"] = "privilege_escalation"
        
        if "error" in msg_lower:

            level = "ERROR"

        elif (
            "critical" in msg_lower
            or "panic" in msg_lower
            or "fatal" in msg_lower
        ):

            level = "CRITICAL"

        user_match = re.search(
            r"\b(?:user|username|for)\s+([a-zA-Z0-9_\-\.]+)\b",
            message,
            re.IGNORECASE
        )

        if user_match:
            parsed_data["user"] = user_match.group(1)

    # -----------------------------
    # Validate Timestamp
    # -----------------------------

    try:

        datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

    except Exception:

        timestamp = datetime.now().isoformat()

    return {
        "id": log_id,
        "timestamp": timestamp,
        "source": source,
        "level": level,
        "message": message,
        "parsed_data": parsed_data,
    }

def process_log(raw_msg: str, source: str):
    """
    Complete processing pipeline.

    Raw Log
        ↓
    Normalize
        ↓
    Save to PostgreSQL
        ↓
    Return normalized event
    """

    try:

        normalized_log = normalize_log(raw_msg, source)

        result = save_parsed_log(normalized_log)

        if result:
         print("✅ Saved")

        else:
         print("❌ Save failed")

        return normalized_log

    except Exception as e:

        print(f"[Collector Error] {e}")

        return None