from flask import Flask, render_template
import os
import json

app = Flask(__name__)

PYTHON_LOG_FOLDER = "Logs"
SURICATA_LOG = "/var/log/suricata/eve.json"


def read_python_logs():
    events = []

    if not os.path.exists(PYTHON_LOG_FOLDER):
        return events

    for filename in os.listdir(PYTHON_LOG_FOLDER):
        if filename.endswith(".jsonl"):
            file_path = os.path.join(PYTHON_LOG_FOLDER, filename)

            try:
                with open(file_path, "r") as file:
                    for line in file:
                        try:
                            event = json.loads(line)
                            event["source"] = "Python IDS"
                            events.append(event)
                        except json.JSONDecodeError:
                            continue
            except OSError:
                continue

    return events


def read_suricata_logs():
    events = []

    if not os.path.exists(SURICATA_LOG):
        return events

    try:
        with open(SURICATA_LOG, "r") as file:
            for line in file:
                try:
                    data = json.loads(line)

                    # We only want actual Suricata alerts
                    if data.get("event_type") != "alert":
                        continue

                    alert = data.get("alert", {})

                    # Convert Suricata format into our dashboard format
                    event = {
                        "timestamp": data.get("timestamp", "Unknown"),
                        "event_type": "suricata_alert",
                        "source_ip": data.get("src_ip", "Unknown"),
                        "severity": convert_suricata_severity(
                            alert.get("severity")
                        ),
                        "message": alert.get(
                            "signature",
                            "Suricata alert"
                        ),
                        "source": "Suricata"
                    }

                    events.append(event)

                except json.JSONDecodeError:
                    continue

    except (OSError, PermissionError) as e:
        print(f"Could not read Suricata log: {e}")

    return events


def convert_suricata_severity(severity):
    if severity == 1:
        return "HIGH"
    elif severity == 2:
        return "MEDIUM"
    else:
        return "LOW"


def read_logs():
    events = read_python_logs()
    events.extend(read_suricata_logs())

    # Newest alerts first
    events.sort(
        key=lambda event: event.get("timestamp", ""),
        reverse=True
    )

    return events


@app.route("/")
def home():
    events = read_logs()

    high_alerts = 0
    event_counts = {}
    blocked_ips = set()

    for event in events:

        if event.get("severity") == "HIGH":
            high_alerts += 1

        event_type = event.get("event_type", "unknown")

        if event_type in event_counts:
            event_counts[event_type] += 1
        else:
            event_counts[event_type] = 1

        # Only count IPs actually blocked by our Python IDS
        if (
            event.get("event_type")
            in ["blacklisted_ip", "port_scan", "high_syn_rate"]
            and event.get("source_ip")
        ):
            blocked_ips.add(event["source_ip"])

    blocked_ip_count = len(blocked_ips)

    return render_template(
        "index.html",
        events=events,
        high_alerts=high_alerts,
        blocked_ip_count=blocked_ip_count,
        event_counts=event_counts
    )


if __name__ == "__main__":
    app.run(debug=True)