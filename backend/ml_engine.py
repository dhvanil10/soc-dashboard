import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import re
import os
import json
import google.generativeai as genai

# ==========================================
# 🤖 INITIALIZE GEMINI AI
# ==========================================
# Ensure your GEMINI_API_KEY is in your environment variables (.env)
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-2.5-flash')

# ==========================================
# 🛡️ THREAT INTELLIGENCE SIGNATURES
# ==========================================
# 1. SQL Injection: Looks for ', --, #, OR 1=1, UNION SELECT
SQLI_PATTERN = re.compile(r"(?:'|%27|--|%2D%2D|#|%23|union.*select|or.*1=1|drop\s+table)", re.IGNORECASE)

# 2. Cross-Site Scripting (XSS): Looks for <script>, javascript:, eval()
XSS_PATTERN = re.compile(r"(?:<|%3C)script(?:>|%3E)|javascript:|onerror=|onload=|eval\(", re.IGNORECASE)

# 3. Command Injection / RCE: Looks for ;, &&, ls, cat, or directory climbing (../)
RCE_PATTERN = re.compile(r"(?:;|%3B|\||\|\||&&)(?:ls|cat|id|whoami|pwd|wget|curl|bash|sh|ping)|(?:\.\./|\.\.\\|%2e%2e%2f)", re.IGNORECASE)

# 4. Sensitive Path Access: Looking for hidden config files
SENSITIVE_PATTERN = re.compile(r"(?:\.env|\.git|wp-admin|config\.php|/etc/passwd|/etc/shadow)", re.IGNORECASE)


def analyze_for_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    # Ensure required columns exist
    for col in ['bytes_sent', 'bytes_received', 'risk_score', 'is_anomaly', 'confidence_score', 'ai_explanation', 'threat_name']:
        if col not in df.columns:
            if col in ['risk_score', 'confidence_score', 'bytes_sent', 'bytes_received']:
                df[col] = 0.0
            elif col == 'is_anomaly':
                df[col] = False
            else:
                df[col] = "None" if col == 'threat_name' else None

    # ==========================================
    # 🧠 VOLUMETRIC FEATURE ENGINEERING
    # ==========================================
    try:
        # Convert time to pandas datetime to group events by the minute
        df['log_time_dt'] = pd.to_datetime(df['log_time'], errors='coerce')
        df['minute_bucket'] = df['log_time_dt'].dt.floor('min')
        
        # Calculate Total Events Per Minute (For Brute Force)
        freq_map = df.groupby(['source_ip', 'minute_bucket']).size().to_dict()
        df['events_per_minute'] = df.apply(lambda row: freq_map.get((row['source_ip'], row['minute_bucket']), 1), axis=1)
        
        # Calculate Blocked Events Per Minute (For Vulnerability Scanning)
        blocked_df = df[df['action'] == 'Blocked']
        blocked_freq_map = blocked_df.groupby(['source_ip', 'minute_bucket']).size().to_dict()
        df['blocked_per_minute'] = df.apply(lambda row: blocked_freq_map.get((row['source_ip'], row['minute_bucket']), 0), axis=1)
        
    except Exception as e:
        print(f"Time parsing error: {e}")
        df['events_per_minute'] = 1
        df['blocked_per_minute'] = 0

    # ==========================================
    # 🤖 ISOLATION FOREST AI (Math Model)
    # ==========================================
    features = ['bytes_sent', 'bytes_received', 'events_per_minute']
    X = df[features].fillna(0)
    
    if len(X) > 5:
        # Train the AI on the fly to find mathematical outliers
        iso_model = IsolationForest(contamination=0.05, random_state=42)
        df['ai_score'] = iso_model.fit_predict(X) # Returns -1 for anomaly, 1 for normal
        decision_scores = iso_model.decision_function(X) 
        
        # Convert weird AI math scores to a clean 0-100 Confidence Score
        norm_scores = (decision_scores - decision_scores.min()) / (decision_scores.max() - decision_scores.min() + 1e-10)
        df['confidence_score'] = (1.0 - norm_scores) * 100
    else:
        df['ai_score'] = 1
        df['confidence_score'] = 10.0

    # ==========================================
    # 🚨 STEP 1: RULE MATCHING (Tagging Anomalies)
    # ==========================================
    for index, row in df.iterrows():
        is_anomaly = False
        threat_name = "None"
        risk_score = float(row.get('confidence_score', 10.0))
        url = str(row.get('url', ''))

        # 1. SQL Injection (SQLi)
        if SQLI_PATTERN.search(url):
            is_anomaly, threat_name, risk_score = True, "SQL Injection (SQLi)", 95.0
            
        # 2. Cross-Site Scripting (XSS)
        elif XSS_PATTERN.search(url):
            is_anomaly, threat_name, risk_score = True, "Cross-Site Scripting (XSS)", 90.0

        # 3. Command Injection / Path Traversal (RCE)
        elif RCE_PATTERN.search(url):
            is_anomaly, threat_name, risk_score = True, "Command Injection (RCE)", 100.0

        # 4. Sensitive Path Access
        elif SENSITIVE_PATTERN.search(url):
            is_anomaly, threat_name, risk_score = True, "Sensitive Path Access", 85.0

        # 5. Vulnerability Scanning (The "404 Storm")
        elif row.get('blocked_per_minute', 0) > 15:
            is_anomaly, threat_name, risk_score = True, "Vulnerability Scanning", 80.0

        # 6. Brute Force / Directory Enumeration
        elif row.get('events_per_minute', 0) > 50:
            is_anomaly, threat_name, risk_score = True, "Volumetric Attack", 85.0

        # 7. Data Exfiltration
        elif row.get('bytes_sent', 0) > 500000:
            is_anomaly, threat_name, risk_score = True, "Data Exfiltration", 90.0

        # 8. AI Behavioral Anomaly
        elif row.get('ai_score') == -1:
            is_anomaly, threat_name, risk_score = True, "Behavioral Anomaly", max(70.0, risk_score)

        # Fallback for safe, normal traffic
        else:
            risk_score = min(15.0, risk_score)

        # Apply results back to the row
        df.at[index, 'is_anomaly'] = is_anomaly
        df.at[index, 'threat_name'] = threat_name
        df.at[index, 'risk_score'] = round(risk_score, 1)
        # Placeholder text, Gemini will overwrite this!
        df.at[index, 'ai_explanation'] = "Hardcoded fallback explanation." if is_anomaly else "Traffic aligns with normal baseline patterns."

   
# ==========================================
    # 🧠 STEP 2: PRIVACY-SAFE GEMINI CHUNKING (BATCHES OF 100)
    # ==========================================
    anomalies_df = df[df['is_anomaly'] == True]
    
    if not anomalies_df.empty:
        total_anomalies = len(anomalies_df)
        print(f"🤖 Found {total_anomalies} anomalies. Scrubbing privacy data...")
        
        # 1. Prepare all logs, completely scrubbing IPs and Users
        all_logs_to_analyze = []
        for idx, row in anomalies_df.iterrows():
            all_logs_to_analyze.append({
                "id": idx,  # Critical: We keep the ID so we know exactly which row this belongs to
                "threat_name": row['threat_name'],
                "user": "[USER_LOGIN]",       # 🔒 PRIVACY MASK
                "source_ip": "[REDACTED_IP]", # 🔒 PRIVACY MASK
                "url": row['url'],          
                "bytes_sent": row['bytes_sent'],
                "action": row['action']
            })

        # 2. Chunk the logs into groups of 100 to prevent Gemini from crashing
        chunk_size = 100
        chunks = [all_logs_to_analyze[i:i + chunk_size] for i in range(0, total_anomalies, chunk_size)]
        
        print(f"📦 Splitting into {len(chunks)} separate Gemini API requests to avoid token limits...")

        # 3. Loop through each chunk and ask Gemini for reports
        for i, chunk in enumerate(chunks):
            print(f"⏳ Processing chunk {i+1} of {len(chunks)}...")
            
            prompt = f"""
            You are an expert Incident Responder. I am sending you a JSON array of {len(chunk)} network logs flagged as Critical Anomalies.
            For EACH log, write a concise, highly technical 3-part incident report.

            IMPORTANT RULE: The IPs and Users have been redacted for privacy. When writing your report, you MUST use the exact text '[REDACTED_IP]' and '[USER_LOGIN]' when referring to the attacker or user. Do not invent IPs.

            Follow this exact format for each report (do NOT use markdown bolding):
            Context: [1 sentence explaining the attack type]
            Trigger Reason: [1 sentence explicitly stating what caused this flag based on the provided log data]
            Mitigation: [1 specific technical step to remediate]

            You MUST return ONLY a valid JSON array of objects. Each object must have an 'id' (matching the input) and an 'explanation' string containing the 3-part report.
            
            Input logs to analyze:
            {json.dumps(chunk, indent=2)}
            """

            try:
                # Call Gemini for this specific chunk
                response = model.generate_content(prompt)
                response_text = response.text
                
                # Strip markdown formatting
                if response_text.startswith("```json"):
                    response_text = response_text[7:-3]
                elif response_text.startswith("```"):
                    response_text = response_text[3:-3]

                ai_reports = json.loads(response_text.strip())
                
                # 4. 💉 INJECT REAL DATA BACK INTO THE REPORTS LOCALLY
                for report in ai_reports:
                    report_id = report.get('id')
                    explanation = report.get('explanation', '')
                    
                    if report_id is not None and report_id in df.index:
                        # Grab the real IP and User from the dataframe
                        real_ip = str(df.at[report_id, 'source_ip'])
                        real_user = str(df.at[report_id, 'user_login'])
                        if real_user == "nan" or not real_user:
                            real_user = "Unknown"
                            
                        # Apply frontend line-breaks
                        formatted_explanation = explanation.replace("Trigger Reason:", "\nTrigger Reason:").replace("Mitigation:", "\nMitigation:")
                        
                        # Swap the placeholders with the real, unmasked data!
                        personalized_explanation = formatted_explanation.replace("[REDACTED_IP]", real_ip).replace("[USER_LOGIN]", real_user).replace("[REDACTED]", real_ip)
                        
                        df.at[report_id, 'ai_explanation'] = personalized_explanation
                        
                print(f"✅ Chunk {i+1} mapped and injected successfully!")

            except Exception as e:
                print(f"⚠️ Gemini API Error on chunk {i+1} (Falling back to default text): {e}")

    # Clean up temporary calculation columns before sending to database
    cols_to_drop = ['log_time_dt', 'minute_bucket', 'events_per_minute', 'blocked_per_minute', 'ai_score']
    for col in cols_to_drop:
        if col in df.columns:
            df = df.drop(columns=[col])

    return df