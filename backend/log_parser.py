import pandas as pd
import re
from datetime import datetime

def parse_zscaler_log(file_path: str) -> pd.DataFrame:
    """
    Smart parser that can handle both standard CSVs and raw Apache/Nginx Access Logs.
    """
    
    # 1. The Regex blueprint to slice up Apache/Nginx log lines
    # Matches: IP - - [Time] "Request" Status Bytes
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<bytes>\S+)'
    )

    parsed_data = []

    try:
        # 2. Open the file and read it line by line
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = log_pattern.search(line)
                if match:
                    data = match.groupdict()

                    # -- Format the Timestamp --
                    try:
                        # Convert "27/Feb/2026:09:00:30 -0800" to "2026-02-27 09:00:30"
                        dt = datetime.strptime(data['time'], '%d/%b/%Y:%H:%M:%S %z')
                        log_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        log_time = data['time']

                    # -- Format the Data Volume --
                    b_sent = data['bytes']
                    bytes_sent = float(b_sent) if b_sent.isdigit() else 0.0

                    # -- Determine Action from HTTP Status --
                    # Status 200/300s are "Allowed", Status 400/500s are "Blocked"
                    status_code = int(data['status'])
                    action = "Allowed" if status_code < 400 else "Blocked"

                    # -- Extract the URL & HTTP Method --
                    # Turns "GET /images/banner.jpg HTTP/1.1" into "GET /images/banner.jpg"
                    req_parts = data['request'].split(' ')
                    method = req_parts[0] if len(req_parts) > 0 else "UNKNOWN"
                    path = req_parts[1] if len(req_parts) > 1 else data['request']
                    url = f"{method} {path}"

                    # -- Map everything to our Dashboard Schema --
                    parsed_data.append({
                        "log_time": log_time,
                        "user_login": f"web_user_{data['ip'].replace('.', '_')}", # Fake user since access logs don't have emails
                        "department": "External",
                        "device_name": "Web Server",
                        "source_ip": data['ip'],
                        "dest_ip": "0.0.0.0",
                        "url": url,
                        "bytes_sent": bytes_sent,
                        "bytes_received": 0.0,
                        "action": action,
                        "threat_name": "None",
                        "risk_score": 0.0,
                        "is_anomaly": False,
                        "confidence_score": 0.0,
                        "ai_explanation": None
                    })

        # 3. If we successfully matched Regex logs, return them!
        if parsed_data:
            return pd.DataFrame(parsed_data)

        # 4. FALLBACK: If Regex failed, try reading it as a standard CSV
        df = pd.read_csv(file_path)
        
        # Ensure all required database columns exist so PostgreSQL doesn't crash
        expected_cols = ["log_time", "user_login", "source_ip", "url", "action", "bytes_sent", "bytes_received", "threat_name"]
        for col in expected_cols:
            if col not in df.columns:
                df[col] = "Unknown" if col in ["user_login", "source_ip", "url", "action"] else 0.0
                
        return df

    except Exception as e:
        print(f"Parser Error: {str(e)}")
        # If absolutely everything fails, return an empty dataframe
        return pd.DataFrame()