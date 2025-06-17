import re
import csv

parsed_logs = []

pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<timestamp>[^\]]+)\]\s"(?P<method>\w+)\s(?P<url>\S+)\s(?P<http_version>[^"]+)"\s(?P<status>\d+)\s(?P<size>\d+)\s"[^"]*"\s"(?P<user_agent>[^"]*)"'

with open("nginx.log",'r') as file:
    for line in file:
        
        match = re.search(pattern,line)

        if match:
            parsed_logs.append(match.groupdict())


csv_file_path = "nginx_logs.csv"

with open(csv_file_path,'w',newline='') as file:
     fieldnames= ['ip','timestamp','method','url','http_version','status','size','user_agent']
     writer = csv.DictWriter(file,fieldnames)
     writer.writeheader()

     writer.writerows(parsed_logs)

        