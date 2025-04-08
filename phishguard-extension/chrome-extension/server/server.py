# server.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import re
import time

app = Flask(__name__)
CORS(app)

try:
    with open('rf_model_combined.pkl', 'rb') as f:
        rf_model = pickle.load(f)
    with open('tfidf_combined.pkl', 'rb') as f:
        tfidf = pickle.load(f)
    with open('tokenizer_combined.pkl', 'rb') as f:
        tokenizer = pickle.load(f)
    lstm_model = load_model('lstm_model_combined.h5')
    print("Models and preprocessors loaded successfully!")
except Exception as e:
    print(f"Error loading models or preprocessors: {e}")
    raise

max_words = 5000
max_len = 200

def clean_email_text(body):
    body = str(body)
    match = re.search(r'(Dear [^\n]+|From: [^\n]+|Subject: [^\n]+)(.*?)(--===============|$)', body, re.DOTALL)
    if match:
        content = match.group(2).strip()
    else:
        content = body.strip()
    content = re.sub(r'<[^>]+>', '', content)
    content = re.sub(r'[^\w\s]', ' ', content)
    content = re.sub(r'\s+', ' ', content)
    return content.lower()

@app.route('/v1/health', methods=['GET'])
def health_check():
    print("Health check requested")
    return jsonify({
        'status': 'online',
        'version': '1.0.0',
        'message': 'API is available'
    }), 200

@app.route('/v1/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json(force=True)  # Force JSON parsing even if Content-Type is off
        print(f"Raw request data: {request.data}")
        print(f"Parsed JSON: {data}")
        email_text = data.get('email_content', '') if data else ''
        print(f"Extracted email_content: '{email_text}' (length: {len(email_text)})")
        
        if not email_text:
            print("No email_content found - returning 400")
            return jsonify({
                'status': 'error',
                'message': 'No email_content provided in the request'
            }), 400

        cleaned_text = clean_email_text(email_text)
        print(f"Cleaned email content (first 100 chars): {cleaned_text[:100]}")

        email_tfidf = tfidf.transform([cleaned_text]).toarray()
        email_seq = tokenizer.texts_to_sequences([cleaned_text])
        email_pad = pad_sequences(email_seq, maxlen=max_len)

        rf_prob = rf_model.predict_proba(email_tfidf)[:, 1][0]
        lstm_prob = lstm_model.predict(email_pad, verbose=0)[0][0]
        ensemble_prob = (rf_prob + lstm_prob) / 2
        prediction = "phishing" if ensemble_prob > 0.9 else "legitimate"

        print(f"RF Prob: {rf_prob:.3f}, LSTM Prob: {lstm_prob:.3f}, Ensemble Prob: {ensemble_prob:.3f}, Prediction: {prediction}")

        return jsonify({
            'prediction': prediction,
            'confidence': float(ensemble_prob),
            'scan_id': f"scan-{int(time.time())}",
            'scan_time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        })
    except Exception as e:
        print(f"Prediction error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)