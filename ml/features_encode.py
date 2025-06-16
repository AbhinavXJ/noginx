from sklearn.datasets import fetch_kddcup99
from sklearn.preprocessing import LabelEncoder

# Load data
df = fetch_kddcup99(percent10=True, as_frame=True).frame

# Decode bytes to strings
for col in ['protocol_type', 'service', 'flag']:
    df[col] = df[col].str.decode('utf-8')

# Create encoders
protocol_encoder = LabelEncoder()
service_encoder = LabelEncoder()
flag_encoder = LabelEncoder()

# Fit encoders
df['protocol_type'] = protocol_encoder.fit_transform(df['protocol_type'])
df['service'] = service_encoder.fit_transform(df['service'])
df['flag'] = flag_encoder.fit_transform(df['flag'])

# Print mappings
print("\nProtocol Type Mapping:")
print({label: i for i, label in enumerate(protocol_encoder.classes_)})

print("\nService Mapping:")
print({label: i for i, label in enumerate(service_encoder.classes_)})

print("\nFlag Mapping:")
print({label: i for i, label in enumerate(flag_encoder.classes_)})
