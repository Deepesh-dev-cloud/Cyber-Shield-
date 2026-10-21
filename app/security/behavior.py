import statistics


def calculate_baseline(attempts):
    """
    Calculate the user's normal typing behavior
    from previous login attempts.
    """

    valid_attempts = [
        attempt for attempt in attempts
        if attempt.typing_speed is not None
        and attempt.average_key_interval is not None
        and attempt.typing_variation is not None
    ]

    if not valid_attempts:
        return None

    wpm_values = [
        attempt.typing_speed
        for attempt in valid_attempts
    ]

    interval_values = [
        attempt.average_key_interval
        for attempt in valid_attempts
    ]

    variation_values = [
        attempt.typing_variation
        for attempt in valid_attempts
    ]

    return {
        "avg_wpm": statistics.mean(wpm_values),
        "avg_key_interval": statistics.mean(interval_values),
        "avg_variation": statistics.mean(variation_values)
    }


def calculate_risk(baseline, current_wpm, current_interval, current_variation):
    """
    Compare the current login behavior with the user's baseline.
    Returns a risk score from 0 to 100.
    """

    if baseline is None:
        return {
            "score": 0,
            "status": "INSUFFICIENT DATA"
        }

    score = 0

    # WPM difference
    wpm_difference = abs(
        current_wpm - baseline["avg_wpm"]
    ) / baseline["avg_wpm"] * 100

    if wpm_difference > 50:
        score += 40
    elif wpm_difference > 30:
        score += 25
    elif wpm_difference > 15:
        score += 10

    # Key interval difference
    interval_difference = abs(
        current_interval - baseline["avg_key_interval"]
    ) / baseline["avg_key_interval"] * 100

    if interval_difference > 50:
        score += 30
    elif interval_difference > 30:
        score += 20
    elif interval_difference > 15:
        score += 10

    # Typing variation difference
    variation_difference = abs(
        current_variation - baseline["avg_variation"]
    ) / max(baseline["avg_variation"], 1) * 100

    if variation_difference > 50:
        score += 30
    elif variation_difference > 30:
        score += 20
    elif variation_difference > 15:
        score += 10

    # Maximum score = 100
    score = min(score, 100)

    if score >= 60:
        status = "HIGH RISK"
    elif score >= 30:
        status = "MEDIUM RISK"
    else:
        status = "LOW RISK"

    return {
        "score": round(score, 2),
        "status": status
    }