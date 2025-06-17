import os
import re
import pandas as pd
from datetime import datetime
import json
import requests
from plyer import notification
import smtplib
from email.mime.text import MIMEText
import time
from dotenv import load_dotenv

load_dotenv()

predict_one_url = os.getenv('PREDICT_ONE_URL')
noginx_mail_id = os.getenv('NOGINX_MAIL_ID')
noginx_mail_password = os.getenv('NOGINX_MAIL_PASSWORD')
receiver_mail_id = os.getenv('RECEIVER_MAIL_ID')




filename = "/var/log/nginx/access.log"

pattern = r'(?P<ip>[\d.:a-fA-F]+)\s+- - \[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s(?P<url>\S+)\s(?P<http_version>[^"]+)"\s(?P<status>\d+)\s(?P<size>\d+)\s"[^"]*"\s"(?P<user_agent>[^"]*)"'

def encode_with_fallback(value,dict):
    return dict.get(value,-1)

def send_alert(df,method,path,user_agent):
    ip = df['ip'].values[0]
    user_agent = user_agent.values[0]
    timestamp = df['timestamp'].values[0]
    path = path.values[0]

    message = (
        f"🚨 Anomaly Detected!\n\n"
        f"IP Address: {ip}\n"
        f"Timestamp: {timestamp}\n"
        f"Path: {path}\n"
        f"User Agent: {user_agent}"
    )

    notification.notify(
        title="🚨 Anomaly Alert!",
        message=message,
        app_name="noginx",
        timeout=10,
        ticker="Anomaly detected",
        toast=False
    )

    s = smtplib.SMTP('smtp.gmail.com', 587)

    s.starttls()
    s.login(noginx_mail_id, noginx_mail_password)
    msg = MIMEText(message, _charset="utf-8")
    msg['Subject'] = "🚨 noginx Anomaly Detected"
    msg['From'] = noginx_mail_id
    msg['To'] = receiver_mail_id

    hi = s.sendmail(noginx_mail_id, receiver_mail_id, msg.as_string())
    print("SMTP Response:", hi)

    s.quit()





    return

encoding_path = os.path.abspath(os.path.join(os.path.dirname(__file__),'..','data','encoder_mappings.json'))

with open(encoding_path, "r") as f:
    encoder_mappings = json.load(f)

with open(filename, 'r') as file:
    file.seek(0, os.SEEK_END)  # Go to end of file

    print("Watching NGINX logs for anomalies...")
    while True:
        line = file.readline()
        if not line:
            time.sleep(1)
            continue

        match = re.search(pattern, line)
        if match:
            df = pd.DataFrame([match.groupdict()])
            df['hour_of_day'] = df['timestamp'].apply(lambda x: int(datetime.strptime(x.split()[0], "%d/%b/%Y:%H:%M:%S").hour))
            df['path'] = df['url'].apply(lambda x: x.split('?')[0])

            df['status'] = df['status'].astype(int)
            df['size'] = df['size'].astype(int)
            cur_method = df['method']
            cur_path = df['path']
            cur_user_agent = df['user_agent']

            df['method'] = df['method'].apply(lambda x: encode_with_fallback(x, encoder_mappings['method']['mapping']))
            df['path'] = df['path'].apply(lambda x: encode_with_fallback(x, encoder_mappings['path']['mapping']))
            df['user_agent'] = df['user_agent'].apply(lambda x: encode_with_fallback(x, encoder_mappings['user_agent']['mapping']))

            feature_df = df[['status', 'size', 'method', 'path', 'user_agent', 'hour_of_day']]
            payload = {"feature": feature_df.iloc[0].to_dict()}

            try:
                res = requests.post(predict_one_url, json=payload)
                is_anomaly = res.json()[0]["anomaly"]

                if is_anomaly:
                    print("🔥 Anomaly Detected")
                    send_alert(df, cur_method, cur_path, cur_user_agent)

            except Exception as e:
                print("Prediction failed:", e)

        else:
            print(" Log line did not match expected format.")
