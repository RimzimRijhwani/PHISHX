from flask import Flask, render_template, request
from feature import FeatureExtraction
from safe_browsing import is_url_safe
import pickle
import pandas as pd

app = Flask(__name__)

model = pickle.load(open("pickle/model.pkl", "rb"))

feature_names = [
    'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'PrefixSuffix-',
    'SubDomains', 'HTTPS', 'DomainRegLen', 'RequestURL', 'InfoEmail',
    'AbnormalURL', 'IframeRedirection', 'AgeofDomain', 'DNSRecording', 'GoogleIndex'
]

@app.route("/", methods=["GET", "POST"])
def index():
    prediction = ""
    if request.method == "POST":
        url = request.form["url"]
        print(f"\n🔍 Checking URL: {url}")

        try:
            is_safe = is_url_safe(url)
            print("✅ Safe Browsing verdict:", is_safe)
        except Exception as e:
            print("❌ Safe Browsing failed:", e)
            is_safe = False

        try:
            extractor = FeatureExtraction(url)
            features = extractor.getFeaturesList()
            print("🧠 Extracted Features:", features)

            features_df = pd.DataFrame([features], columns=feature_names)
            model_result = model.predict(features_df)[0]
            print("📊 ML Model prediction:", model_result)
        except Exception as e:
            prediction = f"⚠️ Feature extraction or prediction error: {e}"
            return render_template("index.html", prediction=prediction)

        # Final verdict logic — prioritizing Safe Browsing
        if not is_safe and model_result == 1:
            prediction = "Unsafe."
        elif not is_safe:
            prediction = "Suspicious (flagged by Google Safe Browsing)"
        elif model_result == 1:
            prediction = "Suspicious (flagged by ML model)"
        else:
            prediction = "URL is safe."

    return render_template("index.html", prediction=prediction)

if __name__ == "__main__":
    app.run(debug=True)
