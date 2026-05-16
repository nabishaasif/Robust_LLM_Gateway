# Secure LLM Gateway
### CSC 262 - Artificial Intelligence | Lab Mid

A security gateway that protects LLM applications from prompt injection, jailbreak attacks, and sensitive data leakage.

## Pipeline
User Input → Injection Detection → Presidio PII Analyzer → Policy Engine → Output

## Features
- Prompt injection and jailbreak detection with scoring
- PII detection and anonymization using Microsoft Presidio
- 3 custom Presidio recognizers (API keys, Internal IDs, Phone numbers)
- Configurable policy decisions (Allow / Mask / Block)
- Latency measurement for all pipeline stages

## Installation

### 1. Clone the repository
git clone https://github.com/nabishaasif/secure-llm-gateway.git
cd secure-llm-gateway

### 2. Create virtual environment
python -m venv venv
venv\Scripts\activate

### 3. Install dependencies
pip install -r requirements.txt

### 4. Download spacy model
python -m spacy download en_core_web_lg

### 5. Run the gateway
python main.py

### 6. Open browser
http://localhost:8000/docs

## Test Scenarios
Send POST request to /analyze with:
{"text": "your input here"}
