import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# 🔹 Step 1: Load dataset
df = pd.read_csv("phishing_dataset.csv")

# 🔹 Debug: Print available columns
print("Available columns:", df.columns)

# 🔹 Step 2: Ensure 'Result' column exists (Labels: 1 = phishing, 0 = safe)
if 'Result' not in df.columns:
    raise KeyError("The 'Result' column (labels) is missing from the dataset. Check the CSV file.")

# 🔹 Step 3: Select Features & Target Variable
# Using existing numerical features (excluding 'index' and 'Result')
X = df.drop(columns=['index', 'Result'])
y = df['Result']

# 🔹 Step 4: Split into Training & Testing Data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 🔹 Step 5: Train the Model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# 🔹 Step 6: Evaluate Model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"✅ Model Training Completed! Accuracy: {accuracy:.2f}")

# 🔹 Step 7: Save the Model
with open("phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Model saved as 'phishing_model.pkl'.")
