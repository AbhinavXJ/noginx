import pandas as pd
import joblib
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from sklearn.datasets import fetch_kddcup99

# Load dataset (10% version)
data = fetch_kddcup99(percent10=True, as_frame=True)
df = data.frame

df.dropna(inplace=True)
df.reset_index(drop="true",inplace=True)

for col in ['protocol_type','service','flag']:
    encoder = LabelEncoder()
    df[col] = encoder.fit_transform(df[col])

X = df.drop(columns=["labels"])
y_true = df["labels"]

model = joblib.load("model.pkl")
y_pred = model.predict(X)

y_true_binary = y_true.apply(lambda x: 1 if x == b'normal.' else -1)

print("Confusion Matrix:")
print(confusion_matrix(y_true_binary, y_pred))

print("\nClassification Report:")
print(classification_report(y_true_binary, y_pred, target_names=["Attack", "Normal"]))

