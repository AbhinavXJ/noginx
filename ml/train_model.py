# train_model.py

from sklearn.datasets import fetch_kddcup99
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest
import joblib


# Load dataset (10% version)
data = fetch_kddcup99(percent10=True, as_frame=True)
df = data.frame
# df['labels'] = df['labels'].apply(lambda x: x.decode('utf-8'))


for col in ['protocol_type','service','flag']:
    encoder = LabelEncoder()
    df[col] = encoder.fit_transform(df[col])

# creating normal dataset where network is Ok
df_normal = df[df['labels']==b'normal.']

X_train  = df_normal.drop(columns='labels')

print(X_train.head())



#training the model
model = IsolationForest(contamination=0.25, random_state=42)
model.fit(X_train)

joblib.dump(model,"model.pkl")
print("Model saved to ml/model.pkl")


