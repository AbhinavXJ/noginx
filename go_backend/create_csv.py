from sklearn.datasets import fetch_kddcup99
import pandas as pd

# Load 10% KDDCup99 dataset
data = fetch_kddcup99(percent10=True, as_frame=True)
df = data.frame.copy()
df['target'] = data.target 


# Drop missing values
df.dropna(inplace=True)

# Keep 5 normal and 5 anomaly rows
df['target'] = df['target'].astype(str)
normal_df = df[df['target'] == 'normal.'].head(5)
anomaly_df = df[df['target'] != 'normal.'].head(5)

# Combine and drop label column
combined_df = pd.concat([normal_df, anomaly_df])
final_df = combined_df.drop(columns=["target"])
final_df = final_df.drop(columns='labels')

# Save to CSV
final_df.to_csv("network_logs.csv", index=False, header=False)
print("CSV created as 'network_logs_sample.csv'")
