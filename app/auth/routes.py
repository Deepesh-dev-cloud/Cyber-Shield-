
from ipaddress import ip_address as parse_ip

from flask import Blueprint, render_template, request
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

from app.database.db import db
from app.database.models import User
from app.database.login_attempt import LoginAttempt
from app.security.behavior import calculate_baseline, calculate_risk


auth = Blueprint("auth", __name__)


def get_client_ip():
    """
    Use CF-Connecting-IP only when the application is
    configured to receive requests through a trusted
    Cloudflare proxy.

    Otherwise, use the direct peer address. Do not
    blindly trust X-Forwarded-For.
    """
    cloudflare_ip = request.headers.get("CF-Connecting-IP", "").strip()

    if cloudflare_ip:
        try:
            # Validate that the value is a valid IP address.
            return str(parse_ip(cloudflare_ip))
        except ValueError:
            pass

    remote_ip = request.remote_addr

    if remote_ip:
        try:
            return str(parse_ip(remote_ip))
        except ValueError:
            pass

    return "Unknown"


# -----------------------------------
# Login
# -----------------------------------

@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    typing_speed = request.form.get("typing_speed", type=float)

    average_key_interval = request.form.get(
        "average_key_interval",
        type=float
    )

    typing_variation = request.form.get(
        "typing_variation",
        type=float
    )

    # Get the client IP candidate
    ip_address = get_client_ip()

    # Temporary diagnostic logs
    print("REMOTE_ADDR:", request.remote_addr)
    print("CF_CONNECTING_IP:", request.headers.get("CF-Connecting-IP"))
    print("Client IP selected:", ip_address)

    # Find user
    user = User.query.filter_by(username=username).first()

    # Validate credentials
    login_success = bool(
        user and check_password_hash(
            user.password_hash,
            password
        )
    )

    # Save login attempt
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

    # Behavioral analysis
    risk_result = None
    baseline = None

    if login_success and typing_speed is not None:

        previous_attempts = LoginAttempt.query.filter_by(
            username=username,
            login_success=True
        ).all()

        # Exclude current login
        previous_attempts = [
            item for item in previous_attempts
            if item.id != attempt.id
        ]

        baseline = calculate_baseline(previous_attempts)

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

    # Return login result
    if login_success:

        print(
            f"LOGIN SUCCESS | Username: {username} | "
            f"IP: {ip_address} | WPM: {typing_speed} | "
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

    print(
        f"LOGIN FAILED | Username: {username} | "
        f"IP: {ip_address} | WPM: {typing_speed}"
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

    print(f"USER REGISTERED | Username: {username}")

    return "Registration successful! <a href='/login'>Login</a>"


# -----------------------------------
# Dashboard
# -----------------------------------

@auth.route("/dashboard")
def dashboard():

    attempts = LoginAttempt.query.order_by(
        LoginAttempt.timestamp.desc()
    ).all()

    if not attempts:
        return "No login attempts recorded yet."

    latest = attempts[0]

    username = latest.username
    ip_address = latest.ip_address

    # Successful attempts with complete behavioral data
    successful_attempts = [
        item for item in attempts
        if item.login_success
        and item.typing_speed is not None
        and item.average_key_interval is not None
        and item.typing_variation is not None
    ]

    # Calculate behavioral baseline
    if successful_attempts:

        baseline_wpm = round(
            sum(item.typing_speed for item in successful_attempts)
            / len(successful_attempts),
            2
        )

        baseline_interval = round(
            sum(item.average_key_interval for item in successful_attempts)
            / len(successful_attempts),
            2
        )

        baseline_variation = round(
            sum(item.typing_variation for item in successful_attempts)
            / len(successful_attempts),
            2
        )

    else:
        baseline_wpm = 0
        baseline_interval = 0
        baseline_variation = 0

    # Calculate behavioral risk
    risk_score = 0

    if successful_attempts and latest.login_success:

        if (
            latest.typing_speed is not None
            and latest.average_key_interval is not None
            and latest.typing_variation is not None
        ):

            if baseline_wpm > 0:
                wpm_percent = (
                    abs(latest.typing_speed - baseline_wpm)
                    / baseline_wpm
                ) * 100

                if wpm_percent > 50:
                    risk_score += 40
                elif wpm_percent > 25:
                    risk_score += 20

            if baseline_interval > 0:
                interval_percent = (
                    abs(
                        latest.average_key_interval
                        - baseline_interval
                    ) / baseline_interval
                ) * 100

                if interval_percent > 100:
                    risk_score += 30
                elif interval_percent > 50:
                    risk_score += 15

            if baseline_variation > 0:
                variation_percent = (
                    abs(
                        latest.typing_variation
                        - baseline_variation
                    ) / baseline_variation
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
