import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

df = pd.read_csv("features.csv")

# Create the 2x3 subplot grid
fig, axes = plt.subplots(2, 3, figsize=(18, 10))
plt.tight_layout(pad=5)

# Plot 1: HTTP Status Code Distribution
sns.countplot(x="status", data=df, ax=axes[0, 0])
axes[0, 0].set_title("HTTP Status Code Distribution")
axes[0, 0].set_xlabel("Status Code")
axes[0, 0].set_ylabel("Count")

# Plot 2: Response Size Distribution
sns.histplot(df["size"], bins=50, kde=True, ax=axes[0, 1])
axes[0, 1].set_title("Distribution of Response Sizes")
axes[0, 1].set_xlabel("Size")
axes[0, 1].set_ylabel("Frequency")

# Plot 3: Requests per Hour
sns.countplot(x="hour_of_day", data=df, ax=axes[0, 2])
axes[0, 2].set_title("Requests per Hour")
axes[0, 2].set_xlabel("Hour of Day")
axes[0, 2].set_ylabel("Request Count")

# Plot 4: HTTP Method Distribution
sns.countplot(x="method", data=df, ax=axes[1, 0])
axes[1, 0].set_title("HTTP Method Distribution")
axes[1, 0].set_xlabel("Method (encoded)")
axes[1, 0].set_ylabel("Count")

# Plot 5: Correlation Heatmap
sns.heatmap(df.corr(), annot=True, cmap="coolwarm", ax=axes[1, 1])
axes[1, 1].set_title("Feature Correlation Heatmap")

# Leave last cell (axes[1, 2]) blank
axes[1, 2].axis('off')

# Show the full grid of plots
plt.show()
