from fastapi import FastAPI
import joblib
from features import extract_features

app = FastAPI()

model = joblib.load("model.pkl")

@app.post("/predict")
def predict(data: dict):
    url = data["url"]

    features = extract_features(url)
    pred = model.predict([features])[0]
    prob = model.predict_proba([features])[0][1]

    return {
        "prediction": int(pred),
        "confidence": float(prob)
    }
@app.get("/health")
def health():
    return {"status": "UP"}