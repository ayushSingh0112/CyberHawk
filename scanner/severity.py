def calculate_severity(base_impact, url, param="", requires_auth=False, complex_exploit=False):
    """
    Dynamic Rule-Based Severity Engine
    Severity = Impact + Exploitability + Sensitivity
    """
    score = base_impact

    # Exploitability Level
    if requires_auth:
        score += 1
    else:
        score += 2  # No auth required

    if complex_exploit:
        score -= 1  # Requires user interaction, multi-step, or blind guessing

    # Sensitivity Level (Data context from keywords)
    target_str = f"{url} {param}".lower()
    if any(k in target_str for k in ['pay', 'checkout', 'card', 'billing', 'wallet', 'bank', 'invoice', 'finance']):
        score += 3  # Financial data
    elif any(k in target_str for k in ['profile', 'user', 'people', 'email', 'social', 'account', 'auth']):
        score += 2  # PII data
    elif any(k in target_str for k in ['api/internal', 'dashboard', 'report', 'admin', 'system']):
        score += 1  # Internal data

    # Boundary Clamp
    if score < 1: score = 1
    if score > 15: score = 15

    # Map to Severity Label
    if score >= 9:
        return 'Critical'
    elif score >= 7:
        return 'High'
    elif score >= 4:
        return 'Medium'
    else:
        return 'Low'
