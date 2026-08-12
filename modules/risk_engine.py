def risk_to_score(risk_level):
    """
    Convert risk level into a numerical score.
    """

    scores = {
        "LOW": 20,
        "MEDIUM": 50,
        "HIGH": 80
    }

    return scores.get(risk_level.upper(), 0)


def calculate_overall_risk(results):
    """
    Calculate the overall anti-forensics risk score.
    """

    if not results:
        return {
            "score": 0,
            "risk_level": "LOW"
        }

    scores = []

    for result in results:
        risk_level = result.get("risk_level", "LOW")
        score = risk_to_score(risk_level)
        scores.append(score)

    average_score = sum(scores) / len(scores)

    if average_score >= 70:
        overall_risk = "HIGH"
    elif average_score >= 40:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    return {
        "score": round(average_score, 2),
        "risk_level": overall_risk
    }