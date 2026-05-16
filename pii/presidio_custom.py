import re
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

class PakistaniCustomPiiRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="CUSTOM_PII",
            patterns=[
                Pattern("PK_CNIC", r"\b\d{5}-\d{7}-\d{1}\b", 1.0),
                Pattern("STUDENT_ID", r"\b[A-Z]{2,4}\d{2}-[A-Z]{3}-\d{3,4}\b", 1.0)
            ],
        )

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        for match in re.finditer(r"\b\d{5}-\d{7}-\d{1}\b", text):
            results.append(RecognizerResult(entity_type="CNIC", start=match.start(), end=match.end(), score=1.0))
        for match in re.finditer(r"\b[A-Z]{2,4}\d{2}-[A-Z]{3}-\d{3,4}\b", text, re.IGNORECASE):
            results.append(RecognizerResult(entity_type="STUDENT_ID", start=match.start(), end=match.end(), score=1.0))
        return results

def detect_composite_pii(text: str, results: list) -> list:
    entity_types = {r.entity_type for r in results}
    composite_flags = []
    if "CNIC" in entity_types or "STUDENT_ID" in entity_types:
        composite_flags.append({
            "type": "HIGH_RISK_SECRET_EXPOSURE",
            "description": "Critical identifiers exposed",
            "risk": "CRITICAL",
        })
    return composite_flags

def build_analyzer() -> AnalyzerEngine:
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
    })
    analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
    
    for rec in list(analyzer.registry.recognizers):
        if rec.supported_entities and any(e in ["DATE_TIME", "NRP", "LOCATION", "ORGANIZATION"] for e in rec.supported_entities):
            analyzer.registry.remove_recognizer(rec.name)
            
    analyzer.registry.add_recognizer(PakistaniCustomPiiRecognizer())
    return analyzer

def analyze_pii(text: str, analyzer: AnalyzerEngine, threshold: float = 0.5) -> dict:
    anonymizer = AnonymizerEngine()
    results = analyzer.analyze(text=text, language="en", score_threshold=threshold)
    calibrated = [r for r in results if r.score >= threshold]
    
    operators = {
        "CNIC": OperatorConfig("replace", {"new_value": "<CNIC>"}),
        "STUDENT_ID": OperatorConfig("replace", {"new_value": "<STUDENT_ID>"}),
        "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
        "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "<PHONE>"}),
    }
    anonymized = anonymizer.anonymize(text=text, analyzer_results=calibrated, operators=operators)
    
    return {
        "entities_found": [{"type": r.entity_type, "score": round(r.score, 3), "value": text[r.start:r.end]} for r in calibrated],
        "composite_flags": detect_composite_pii(text, calibrated),
        "anonymized_text": anonymized.text,
        "has_pii": len(calibrated) > 0,
    }