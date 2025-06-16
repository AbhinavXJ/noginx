import joblib
from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import List, Dict
import pandas as pd

class Features(BaseModel):
    features: List[Dict[str, float]]

model = joblib.load("model.pkl")
app = FastAPI()

@app.post("/predict")
async def predict(input: Features):
    df = pd.DataFrame(input.features)
    df = df.astype("float64") 

    preds = model.predict(df)
    results = [{"anomaly": bool(pred == -1)} for pred in preds]

    print(results)

    return results

