def _get_risk_level(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def score_analysis(pe_data: dict, string_data: dict) -> dict:
    """
    Build a beginner-friendly heuristic risk score.
    This is a project-defined scoring model, not a malware verdict.
    """
    score = 0
    risk_factors = []

    sections = pe_data.get("sections", [])
    suspicious_imports = pe_data.get("suspicious_imports", [])
    interesting_strings = string_data.get("interesting_strings", {})

    high_entropy_sections = [
        section["name"] or "<blank>"
        for section in sections
        if section.get("entropy", 0) >= 7.4
    ]

    rwx_sections = [
        section["name"] or "<blank>"
        for section in sections
        if section.get("permissions", {}).get("write")
        and section.get("permissions", {}).get("execute")
    ]

    suspicious_import_categories = {
        item["category"] for item in suspicious_imports if item.get("category")
    }

    url_count = len(interesting_strings.get("url", []))
    ipv4_count = len(interesting_strings.get("ipv4", []))
    registry_count = len(interesting_strings.get("registry_key", []))
    command_hint_count = len(interesting_strings.get("command_hint", []))

    # Section-based scoring
    if high_entropy_sections:
        points = min(25, len(high_entropy_sections) * 15)
        score += points
        risk_factors.append(
            f"High-entropy sections found: {', '.join(high_entropy_sections)} (+{points})"
        )

    if rwx_sections:
        points = min(25, len(rwx_sections) * 20)
        score += points
        risk_factors.append(
            f"Writable + executable sections found: {', '.join(rwx_sections)} (+{points})"
        )

    # Import-based scoring
    if suspicious_imports:
        points = min(30, len(suspicious_imports) * 5)
        score += points
        risk_factors.append(
            f"Suspicious API matches found: {len(suspicious_imports)} (+{points})"
        )

    if suspicious_import_categories:
        points = min(15, len(suspicious_import_categories) * 4)
        score += points
        risk_factors.append(
            "Suspicious API categories present: "
            f"{', '.join(sorted(suspicious_import_categories))} (+{points})"
        )

    # String-based scoring
    if registry_count > 0:
        score += 8
        risk_factors.append(f"Registry-related strings found: {registry_count} (+8)")

    if command_hint_count > 0:
        score += 8
        risk_factors.append(f"Command execution hints found: {command_hint_count} (+8)")

    if url_count > 0:
        score += 5
        risk_factors.append(f"URL strings found: {url_count} (+5)")

    if ipv4_count > 0:
        score += 5
        risk_factors.append(f"IPv4 strings found: {ipv4_count} (+5)")

    # Cap final score
    score = min(score, 100)

    return {
        "risk_assessment": {
            "risk_score": score,
            "risk_level": _get_risk_level(score),
            "risk_factors": risk_factors,
            "indicator_counts": {
                "high_entropy_sections": len(high_entropy_sections),
                "rwx_sections": len(rwx_sections),
                "suspicious_imports": len(suspicious_imports),
                "suspicious_import_categories": len(suspicious_import_categories),
                "url_strings": url_count,
                "ipv4_strings": ipv4_count,
                "registry_strings": registry_count,
                "command_hint_strings": command_hint_count,
            },
            "note": "Heuristic score only. This is a triage aid, not a malware verdict.",
        }
    }