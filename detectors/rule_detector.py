import re

# Course specified explicit injection/jailbreak matching patterns
INJECTION_PATTERNS = [
    (r"you are now", 0.7),
    (r"pretend (you are|to be)", 0.7),
    (r"do anything now", 0.85),
    (r"jailbreak", 0.9),
    (r"system prompt", 0.6),
    (r"reveal your (instructions|prompt|system)", 0.85),
    (r"act as (if you have no|without) (restrictions|limits)", 0.9),
    (r"forget (your|all) (rules|guidelines|training)", 0.85),
    (r"<\|.*?\|>", 0.8),
    (r"\[INST\]|\[\/INST\]", 0.75),
    (r"bypass (safety|filter|content)", 0.85),
    (r"نظرا نداز کریں|سسٹم پرامپٹ", 0.85),  # Urdu Injection
    (r"이전 지침을 무시하고", 0.9),         # Korean Injection
]

def get_rule_score(text: str) -> float:
    """Calculates rule-based injection risk using regular expressions."""
    text_lower = text.lower()
    highest_score = 0.0
    for pattern, score in INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            if score > highest_score:
                highest_score = score
    return highest_score