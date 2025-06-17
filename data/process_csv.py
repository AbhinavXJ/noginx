import pandas as pd
import csv
from datetime import datetime
from sklearn.preprocessing import LabelEncoder,StandardScaler
import json


df = pd.read_csv('nginx_logs.csv')

df['hour_of_day'] = df['timestamp'].apply(lambda x: int(datetime.strptime(x.split()[0], "%d/%b/%Y:%H:%M:%S").hour))
df['path'] = df['url'].apply(lambda x: x.split('?')[0])

df['status'] = df['status'].astype(int)
df['size'] = df['size'].astype(int)

#creating encoders 
method_encoder = LabelEncoder()
path_encoder = LabelEncoder()
user_agent_encoder = LabelEncoder()

# Fit encoders
df['method'] = method_encoder.fit_transform(df['method'])       
df['path'] = path_encoder.fit_transform(df['path'])              
df['user_agent'] = user_agent_encoder.fit_transform(df['user_agent'])




print(df.head())

feature_df = df[['status', 'size', 'method', 'path', 'user_agent', 'hour_of_day']]


feature_df.to_csv("features.csv", index=False)

# Save encoder mappings
encoder_mappings = {
    'method': {
        'classes': method_encoder.classes_.tolist(),
        'mapping': {label: int(idx) for idx, label in enumerate(method_encoder.classes_)}
    },
    'path': {
        'classes': path_encoder.classes_.tolist(),
        'mapping': {label: int(idx) for idx, label in enumerate(path_encoder.classes_)}
    },
    'user_agent': {
        'classes': user_agent_encoder.classes_.tolist(),
        'mapping': {label: int(idx) for idx, label in enumerate(user_agent_encoder.classes_)}
    }
}

with open("encoder_mappings.json", "w") as f:
    json.dump(encoder_mappings, f, indent=4)

print("[✓] Encoders saved to encoder_mappings.json")
print(df.head())
