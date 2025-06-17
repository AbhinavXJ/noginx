# train_model.py
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib


df = pd.read_csv("features.csv")


X_train = df


#training the model
model = IsolationForest(contamination="auto", random_state=42)
model.fit(X_train)

joblib.dump(model,"model.pkl")
print("Model saved to model.pkl")


