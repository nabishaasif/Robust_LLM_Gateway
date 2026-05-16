from langdetect import detect, DetectorFactory
DetectorFactory.seed = 42

def detect_language(text: str) -> str:
    if not text or not text.strip():
        return "en"
    try:
        return detect(text.strip())
    except Exception:
        return "en"