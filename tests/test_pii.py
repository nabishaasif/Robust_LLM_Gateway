import pytest
from pii.presidio_custom import build_analyzer, analyze_pii

analyzer = build_analyzer()

def test_custom_pakistani_cnic_extraction():
    text = "My identity registration card number is 35202-1234567-1."
    res = analyze_pii(text, analyzer)
    
    assert res["has_pii"] is True
    entity_types = [e["type"] for e in res["entities_found"]]
    assert "CNIC" in entity_types
    assert "<CNIC>" in res["anonymized_text"]

def test_student_id_masking():
    text = "Student database profile key is FA21-BCS-123."
    res = analyze_pii(text, analyzer)
    
    assert res["has_pii"] is True
    entity_types = [e["type"] for e in res["entities_found"]]
    assert "STUDENT_ID" in entity_types
    assert "<STUDENT_ID>" in res["anonymized_text"]