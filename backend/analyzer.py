import pandas as pd

def analyze_logs(data):

    summary = {
        "total_logs": len(data),
        "users": data["user"].nunique(),
        "ips": data["ip"].nunique(),
        "failed_logins": len(data[data["action"] == "failed_login"])
    }

    # suspicious IP detection
    failed_counts = data[data["action"] == "failed_login"].groupby("ip").size()
    suspicious_ips = failed_counts[failed_counts >= 3]

    return summary, suspicious_ips