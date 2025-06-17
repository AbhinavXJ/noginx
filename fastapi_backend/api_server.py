import joblib
from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import List, Dict
import pandas as pd
import os

class Features(BaseModel):
    features: List[Dict[str, int]]

class Feature(BaseModel):
    feature: Dict[str,int]

model_path = os.path.join(os.path.dirname(__file__),'..','data','model.pkl')
model_path = os.path.abspath(model_path)

EXPECTED_FEATURES = ["status", "size", "method", "path", "user_agent", "hour_of_day"]


model = joblib.load(model_path)
app = FastAPI()

@app.get("/")
async def root():
    return {"message":"server is running live"}

@app.post("/predict")
async def predict(input: Features):
    df = pd.DataFrame(input.features)
    df = df.astype("int")
    df = df[EXPECTED_FEATURES]
    preds = model.predict(df)
    results = [{"anomaly": bool(pred == -1)} for pred in preds]

    print(results)

    return results

@app.post("/predict_one")
async def predict(input: Feature):
    df = pd.DataFrame([input.feature])
    df = df.astype("int")
    df = df[EXPECTED_FEATURES]
    preds = model.predict(df)
    results = [{"anomaly": bool(pred == -1)} for pred in preds]

    print(results)

    return results

