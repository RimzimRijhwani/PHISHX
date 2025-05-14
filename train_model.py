import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Load the improved balanced dataset
df = pd.read_csv("phishing_retrained_dataset.csv")  

# Define the top 15 predictive features
features = [
    'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'PrefixSuffix-',
    'SubDomains', 'HTTPS', 'DomainRegLen', 'RequestURL', 'InfoEmail',
    'AbnormalURL', 'IframeRedirection', 'AgeofDomain', 'DNSRecording', 'GoogleIndex'
]

X = df[features]
y = df['class']

# Split and train model
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Save the trained model
with open("pickle/model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Model trained on 15 features and saved to pickle/model.pkl")
