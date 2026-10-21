from flask import Blueprint, render_template, request
from werkzeug.security import generate_password_hash, check_password_hash

from app.database.db import db
from app.database.models import User
from app.database.login_attempt import LoginAttempt

from app.security.behavior import calculate_baseline, calculate_risk


auth = Blueprint("auth", __name__)


@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    # -----------------------------
    # 1. Get login information
    # -----------------------------

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # Behavioral data sent from login.html
    typing_speed = request.form.get("typing_speed", type=float)
    average_key_interval = request.form.get(
        "average_key_interval",
        type=float
    )
    typing_variation = request.form.get(
        "typing_variation",
        type=float
    )

    # -----------------------------
    # 2. Get IP address
    # -----------------------------

    ip_address = request.remote_addr or "Unknown"

    # -----------------------------
    # 3. Find user
    # -----------------------------

    user = User.query.filter_by(
        username=username
    ).first()

    login_success = False

    # -----------------------------
    # 4. Check username/password
    # -----------------------------

    if user and check_password_hash(
        user.password_hash,
        password
    ):
        login_success = True

    # -----------------------------
    # 5. Save login attempt
    # -----------------------------

    attempt = LoginAttempt(
        username=username,
        ip_address=ip_address,
        login_success=login_success,
        typing_speed=typing_speed,
        average_key_interval=average_key_interval,
        typing_variation=typing_variation
    )

    db.session.add(attempt)
    db.session.commit()

    # -----------------------------
    # 6. Behavioral analysis
    # -----------------------------

    risk_result = None
    baseline = None

    if login_success and typing_speed is not None:

        previous_attempts = LoginAttempt.query.filter_by(
            username=username,
            login_success=True
        ).all()

        # Exclude current attempt from baseline
        previous_attempts = [
            a for a in previous_attempts
            if a.id != attempt.id
        ]

        baseline = calculate_baseline(
            previous_attempts
        )

        if (
            baseline
            and average_key_interval is not None
            and typing_variation is not None
        ):

            risk_result = calculate_risk(
                baseline,
                typing_speed,
                average_key_interval,
                typing_variation
            )

    # -----------------------------
    # 7. Console logging
    # -----------------------------

    if login_success:

        print(
            f"LOGIN SUCCESS | "
            f"Username: {username} | "
            f"IP: {ip_address} | "
            f"WPM: {typing_speed} | "
            f"Avg Key Interval: {average_key_interval} ms | "
            f"Variation: {typing_variation} ms"
        )

        if risk_result:
            print(
                f"RISK SCORE: {risk_result['score']} | "
                f"STATUS: {risk_result['status']}"
            )

        return render_template(
            "login_success.html",
            risk=risk_result,
            baseline=baseline
        )

    else:

        print(
            f"LOGIN FAILED | "
            f"Username: {username} | "
            f"IP: {ip_address} | "
            f"WPM: {typing_speed}"
        )

        return "Invalid username or password!", 401


# -----------------------------------
# Registration
# -----------------------------------

@auth.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return "Username and password are required!", 400

    existing_user = User.query.filter_by(
        username=username
    ).first()

    if existing_user:
        return "Username already exists!", 409

    password_hash = generate_password_hash(password)

    user = User(
        username=username,
        password_hash=password_hash
    )

    db.session.add(user)
    db.session.commit()

    print(
        f"USER REGISTERED | Username: {username}"
    )

    return "Registration successful! <a href='/login'>Login</a>"
@auth.route("/dashboard")
def dashboard():

    # Get all login attempts
    attempts = LoginAttempt.query.order_by(
        LoginAttempt.timestamp.desc()
    ).all()

    # If there are no login attempts
    if not attempts:
        return "No login attempts recorded yet."

    # Latest login attempt
    latest = attempts[0]

    username = latest.username
    ip_address = latest.ip_address

    # Get successful attempts for behavioral baseline
    successful_attempts = [
        attempt for attempt in attempts
        if attempt.login_success
        and attempt.typing_speed is not None
        and attempt.average_key_interval is not None
        and attempt.typing_variation is not None
    ]

    # Calculate baseline
    if successful_attempts:

        baseline_wpm = round(
            sum(a.typing_speed for a in successful_attempts)
            / len(successful_attempts),
            2
        )

        baseline_interval = round(
            sum(a.average_key_interval for a in successful_attempts)
            / len(successful_attempts),
            2
        )

        baseline_variation = round(
            sum(a.typing_variation for a in successful_attempts)
            / len(successful_attempts),
            2
        )

    else:

        baseline_wpm = 0
        baseline_interval = 0
        baseline_variation = 0

    # Calculate current risk again for dashboard
    risk_score = 0

    if successful_attempts and latest.login_success:

        # WPM difference
        wpm_difference = abs(
            latest.typing_speed - baseline_wpm
        )

        # Key interval difference
        interval_difference = abs(
            latest.average_key_interval - baseline_interval
        )

        # Typing variation difference
        variation_difference = abs(
            latest.typing_variation - baseline_variation
        )

        # Simple behavioral risk scoring
        if baseline_wpm > 0:
            wpm_percent = (
                wpm_difference / baseline_wpm
            ) * 100

            if wpm_percent > 50:
                risk_score += 40
            elif wpm_percent > 25:
                risk_score += 20

        if baseline_interval > 0:
            interval_percent = (
                interval_difference / baseline_interval
            ) * 100

            if interval_percent > 100:
                risk_score += 30
            elif interval_percent > 50:
                risk_score += 15

        if baseline_variation > 0:
            variation_percent = (
                variation_difference / baseline_variation
            ) * 100

            if variation_percent > 100:
                risk_score += 30
            elif variation_percent > 50:
                risk_score += 15

        risk_score = min(risk_score, 100)

    return render_template(
        "dashboard.html",
        username=username,
        ip_address=ip_address,
        attempts=attempts[:10],
        baseline_wpm=baseline_wpm,
        baseline_interval=baseline_interval,
        baseline_variation=baseline_variation,
        risk_score=risk_score
    )