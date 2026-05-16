def apply_policy(injection_result: dict, pii_result: dict, config: dict) -> dict:
    rule_score = injection_result["rule_score"]
    semantic_score = injection_result["semantic_score"]
    
    block_threshold = config["injection_detection"]["block_threshold"]
    pii_weight = config["policy"].get("pii_weight", 0.1)
    secret_weight = config["policy"].get("secret_weight", 0.2)
    
    base_risk = max(rule_score, semantic_score)
    additional_weight = 0.0
    reason_codes = []
    
    if rule_score >= block_threshold:
        reason_codes.append("RULE_BASED_INJECTION_DETECTED")
    if semantic_score >= block_threshold:
        reason_codes.append("SEMANTIC_INJECTION_DETECTED")
        
    if pii_result["has_pii"]:
        has_critical_secret = any(e["type"] in ["CNIC", "API_KEY"] for e in pii_result["entities_found"])
        if has_critical_secret:
            additional_weight += secret_weight
            reason_codes.append("CRITICAL_SECRET_EXPOSURE")
        else:
            additional_weight += pii_weight
            reason_codes.append("STANDARD_PII_EXPOSURE")
            
    final_risk = min(base_risk + additional_weight, 1.0)
    
    # Critical Decision Matrix Routing Block Check
    if "RULE_BASED_INJECTION_DETECTED" in reason_codes or "SEMANTIC_INJECTION_DETECTED" in reason_codes or base_risk >= block_threshold:
        return {
            "decision": "BLOCK",
            "final_risk": round(final_risk, 3),
            "reason_codes": reason_codes if reason_codes else ["HIGH_RISK_INJECTION"],
            "safe_text": None
        }
        
    if pii_result["has_pii"]:
        return {
            "decision": "MASK",
            "final_risk": round(final_risk, 3),
            "reason_codes": reason_codes,
            "safe_text": pii_result["anonymized_text"]
        }
        
    return {
        "decision": "ALLOW",
        "final_risk": round(final_risk, 3),
        "reason_codes": ["SAFE_PROMPT"],
        "safe_text": pii_result.get("anonymized_text") or "N/A"
    }