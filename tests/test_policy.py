import pytest
from policy.policy_engine import apply_policy

mock_config = {
    "injection_detection": {"block_threshold": 0.60},
    "policy": {"default_action": "mask", "pii_weight": 0.15, "secret_weight": 0.25}
}

def test_policy_allow_routing():
    inj_res = {"rule_score": 0.0, "semantic_score": 0.12}
    pii_res = {"has_pii": False, "entities_found": [], "anonymized_text": "Hello"}
    
    decision = apply_policy(inj_res, pii_res, mock_config)
    assert decision["decision"] == "ALLOW"

def test_policy_mask_routing():
    inj_res = {"rule_score": 0.0, "semantic_score": 0.15}
    pii_res = {"has_pii": True, "entities_found": [{"type": "CNIC"}], "anonymized_text": "Masked"}
    
    decision = apply_policy(inj_res, pii_res, mock_config)
    assert decision["decision"] == "MASK"