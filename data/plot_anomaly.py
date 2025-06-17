import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# Load expected feature columns
EXPECTED_FEATURES = ["status", "size", "method", "path", "user_agent", "hour_of_day"]

# 1. Load your data
df = pd.read_csv("features.csv")

# 2. Load trained model
model = joblib.load("model.pkl")

# 3. Filter and preprocess data
df = df[EXPECTED_FEATURES].apply(pd.to_numeric, errors='coerce').dropna().astype("int")

# 4. Predict anomalies
df["prediction"] = model.predict(df)

# 5. Map prediction to human-readable labels for legend
df["label"] = df["prediction"].map({1: "Normal", -1: "Anomaly"})

# 6. Plot with seaborn
plt.figure(figsize=(10, 6))
sns.scatterplot(
    data=df,
    x="size",
    y="user_agent",
    hue="label",
    palette={"Normal": "blue", "Anomaly": "red"},
    alpha=0.6
)

plt.title("Anomaly Detection: Blue = Normal, Red = Anomaly")
plt.xlabel("size")
plt.show()

