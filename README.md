# CyberSentry: Real-Time Phishing Threat Identification

An intelligent, multi-modal framework for detecting phishing attempts in real-time using hybrid machine learning. Features a Chrome extension (PhishGuard) for browser-based detection and a Flask API backend.

[![GitHub](https://img.shields.io/badge/GitHub-Repository-black?logo=github)](https://github.com/gokulsatya/phishguard-extension)
![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange.svg)
![Chrome Extension](https://img.shields.io/badge/Chrome-Manifest%20V3-yellow.svg)

## Overview

CyberSentry leverages both Random Forest and LSTM models trained on diverse datasets, forming a probabilistic ensemble capable of accurately classifying suspicious messages. The system achieves **94% accuracy** on email datasets and **91% accuracy** on mixed-format datasets.

## Features

- **Real-time Detection**: Analyzes emails and URLs instantly within Gmail
- **Hybrid ML Approach**: Combines Random Forest (keyword patterns) + LSTM (sequential patterns)
- **Chrome Extension**: Browser-integrated scanning with visual warnings
- **Privacy-Preserving**: All inference runs locally via Flask API
- **User Feedback**: Continuous improvement through user corrections

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Chrome Extension                         │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │ Popup UI │──│ Service      │──│ Content Scripts       │  │
│  │          │  │ Worker       │  │ (DOM Scanner)         │  │
│  └──────────┘  └──────────────┘  └───────────────────────┘  │
└─────────────────────────┬───────────────────────────────────┘
                          │ REST API
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      Flask API                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ Auth         │  │ Rate         │  │ Input            │   │
│  │ Middleware   │  │ Limiting     │  │ Validation       │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              ML Ensemble Model                        │   │
│  │  ┌─────────────────┐    ┌─────────────────────────┐  │   │
│  │  │ Random Forest   │    │ LSTM Neural Network     │  │   │
│  │  │ (TF-IDF)        │    │ (Sequential Patterns)   │  │   │
│  │  └─────────────────┘    └─────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
├── chrome-extension/
│   ├── manifest.json              # Extension configuration (Manifest V3)
│   ├── background/
│   │   └── service-worker.js      # Background service worker
│   ├── content-scripts/
│   │   ├── dom-scanner.js         # Email content extraction
│   │   └── network-monitor.js     # Request monitoring
│   ├── popup-ui/
│   │   ├── popup.html/js/css      # Extension popup interface
│   │   ├── login.html/js          # Authentication UI
│   │   └── api-client.js          # API communication
│   └── shared/
│       ├── error-types.js         # Error handling
│       └── validators.js          # Input validation
│
└── flask-api/
    ├── run.py                     # Application entry point
    ├── requirements.txt           # Python dependencies
    ├── .env                       # Environment configuration
    └── app/
        ├── __init__.py            # Flask app factory
        ├── error_handlers.py      # Global error handling
        ├── models/
        │   ├── phishing_model.py  # ML model interface
        │   ├── rf_model.pkl       # Trained Random Forest
        │   ├── lstm_model.h5      # Trained LSTM
        │   ├── tfidf.pkl          # TF-IDF vectorizer
        │   └── tokenizer.pkl      # Text tokenizer
        ├── routes/
        │   ├── api.py             # Prediction endpoints
        │   └── auth.py            # Authentication endpoints
        └── security/
            ├── auth_middleware.py # JWT authentication
            ├── jwt_utils.py       # Token utilities
            └── input_validator.py # Request validation
```

## Installation

### Prerequisites

- Python 3.10+
- Google Chrome browser
- Node.js (optional, for development)

### Backend Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/gokulsatya/phishguard-extension.git
   cd phishguard-extension/flask-api
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

5. **Run the server**
   ```bash
   python run.py
   ```
   The API will be available at `http://127.0.0.1:5000`

### Chrome Extension Setup

1. **Open Chrome Extensions**
   - Navigate to `chrome://extensions/`
   - Enable "Developer mode" (top right)

2. **Load the extension**
   - Click "Load unpacked"
   - Select the `chrome-extension/` directory

3. **Verify installation**
   - The PhishGuard icon should appear in your toolbar
   - Click it to open the popup interface

## Usage

### Chrome Extension

1. **Navigate to Gmail** (`https://mail.google.com`)
2. **Open an email** you want to scan
3. **Click the PhishGuard icon** in your toolbar
4. **Click "Scan Current Page"**
5. **View results** - verdict (Safe/Phishing) and confidence score

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/predict` | POST | Analyze email/URL for phishing |
| `/v1/health` | GET | API health check |
| `/v1/feedback` | POST | Submit prediction feedback |
| `/v1/stats` | GET | Usage statistics |
| `/v1/auth/login` | POST | User authentication |

#### Example Request

```bash
curl -X POST http://127.0.0.1:5000/v1/predict \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "email_content": "Congratulations! You have won a $1000 gift card...",
    "scan_type": "REALTIME"
  }'
```

#### Example Response

```json
{
  "prediction": "phishing",
  "confidence": 0.94,
  "scan_id": "scan-1234567890",
  "scan_time": "2025-04-17T13:04:21Z",
  "features_analyzed": ["text_patterns", "sequential_patterns"],
  "model_used": "ensemble"
}
```

## Model Performance

| Dataset | Accuracy | Precision | Recall | F1-Score |
|---------|----------|-----------|--------|----------|
| Email Dataset | 94% | 0.93 | 0.95 | 0.94 |
| Mixed Dataset | 91% | 0.89 | 0.92 | 0.90 |

## Technologies

### Backend
- **Flask** - Web framework
- **Flask-CORS** - Cross-origin resource sharing
- **Flask-Limiter** - Rate limiting (10 req/min)
- **Flask-Talisman** - Security headers
- **PyJWT** - JWT authentication
- **scikit-learn** - Random Forest model
- **TensorFlow/Keras** - LSTM model

### Frontend (Chrome Extension)
- **Manifest V3** - Latest Chrome extension API
- **JavaScript** - UI logic and API communication
- **HTML/CSS** - Popup interface

## Security Features

- TLS 1.3 encryption (production)
- JWT authentication with 30-minute expiry
- Rate limiting (10 requests/minute)
- Input validation and sanitization
- Content Security Policy headers
- CORS restrictions

## Development

### Running Tests

```bash
cd flask-api
pytest tests/ -v --cov=app
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DEBUG` | Enable debug mode | `True` |
| `PORT` | Server port | `5000` |
| `JWT_SECRET` | JWT signing key | (required) |
| `JWT_EXPIRATION` | Token expiry (seconds) | `1800` |
| `ALLOWED_ORIGINS` | CORS allowed origins | `chrome-extension://*` |

## Team

- **Mohammed Fouzan Aamiri** - Model Training, Chrome Extension
- **Gokul Sathiyamurthy** - Chrome Extension Development
- **Jagdeep Kainth** - Dataset Collection, Flask API Integration
- **Yveto Meus** - Web UI Development

*Pace University - Cybersecurity Capstone Project*

## Future Enhancements

- [ ] Multilingual email support
- [ ] Lighter models for resource-constrained environments
- [ ] Cloud deployment (AWS/GCP/Azure)
- [ ] Browser support for Firefox and Edge
- [ ] Real-time model retraining pipeline

## References

1. Wang et al. (2019) - PDRCNN: Deep Learning for Phishing Detection
2. Gupta et al. (2021) - Real-time Phishing Detection with Random Forest
3. Thaçi et al. (2024) - NoPhish Chrome Extension
4. Pranaya et al. (2024) - PHISHSNAP Ensemble Learning

## License

This project is developed for academic purposes as part of the Pace University Cybersecurity Capstone.

---

<p align="center">
  <strong>CyberSentry</strong> - Defending against phishing, one email at a time.
</p>
