
import ipaddress
import re
from urllib.parse import urlparse

import cv2
import numpy as np

from flask import render_template, request
from app.link_analyzer import link_analyzer


# ==================================================
# 1. URL ANALYSIS ENGINE
# ==================================================

def analyse_url(raw_url):
    raw_url = (raw_url or "").strip()

    result = {
        "url": raw_url,
        "score": 0,
        "level": "Low",
        "findings": [],
        "error": None,
    }

    if not raw_url:
        result["error"] = "Please enter a URL."
        return result

    if len(raw_url) > 2048:
        result["error"] = "The URL cannot exceed 2048 characters."
        return result

    if any(ord(char) < 32 for char in raw_url):
        result["error"] = "The URL contains invalid control characters."
        return result

    try:
        parsed = urlparse(raw_url)

        if parsed.scheme.lower() not in ("http", "https"):
            result["error"] = (
                "The URL must start with http:// or https://."
            )
            return result

        hostname = parsed.hostname

        if not hostname:
            result["error"] = "The URL does not contain a valid hostname."
            return result

        hostname = hostname.encode("idna").decode("ascii").lower()

        # Validate the port if one is supplied.
        _ = parsed.port

    except (ValueError, UnicodeError):
        result["error"] = "The URL format is invalid."
        return result

    score = 0
    findings = []

    def flag(points, message):
        nonlocal score
        score += points
        findings.append(message)

    # Check for HTTP instead of HTTPS.
    if parsed.scheme.lower() == "http":
        flag(10, "The URL does not use HTTPS.")

    # Check for user information before the hostname.
    if parsed.username is not None or parsed.password is not None:
        flag(
            25,
            "The URL contains user information before its hostname."
        )

    # Check for punycode labels.
    if "xn--" in hostname:
        flag(
            20,
            "The hostname contains a punycode label."
        )

    # Check whether the hostname is an IP address.
    try:
        ipaddress.ip_address(hostname)
        flag(
            20,
            "The hostname is an IP address instead of a domain name."
        )
    except ValueError:
        pass

    # Check for an unusually large number of subdomains.
    if len(hostname.split(".")) >= 5:
        flag(
            10,
            "The hostname contains many subdomain labels."
        )

    # Check URL length.
    if len(raw_url) > 150:
        flag(10, "The URL is unusually long.")

    # Check for words sometimes used in phishing URLs.
    suspicious_words = (
        r"login|verify|account|password|wallet|"
        r"secure|update|confirm|signin"
    )

    if re.search(
        suspicious_words,
        (hostname + parsed.path).lower()
    ):
        flag(
            10,
            "The URL contains account-related words sometimes used in phishing."
        )

    # Keep the score between 0 and 100.
    score = min(score, 100)

    if score >= 40:
        level = "High"
    elif score >= 15:
        level = "Medium"
    else:
        level = "Low"

    if not findings:
        findings.append(
            "No suspicious patterns were detected. "
            "This does not guarantee that the URL is safe."
        )

    result.update({
        "score": score,
        "level": level,
        "findings": findings,
    })

    return result


# ==================================================
# 2. LINK ANALYSER AND QR CODE ANALYSER
# ==================================================

@link_analyzer.route("/scanner", methods=["GET", "POST"])
def scanner_home():

    result = None
    qr_message = None
    qr_result = None

    if request.method == "POST":

        # ------------------------------------------
        # A. PROCESS QR CODE IMAGE
        # ------------------------------------------

        qr_file = request.files.get("qr")

        if qr_file and qr_file.filename:

            allowed_types = {
                "image/png",
                "image/jpeg",
                "image/webp",
            }

            if qr_file.mimetype not in allowed_types:
                qr_message = (
                    "Unsupported image type. "
                    "Upload a PNG, JPG, or WebP image."
                )

            else:
                # Read at most 5 MB plus one byte to detect oversized files.
                image_bytes = qr_file.read(
                    5 * 1024 * 1024 + 1
                )

                if len(image_bytes) > 5 * 1024 * 1024:
                    qr_message = (
                        "The image exceeds the 5 MB upload limit."
                    )

                elif not image_bytes:
                    qr_message = "The uploaded image is empty."

                else:
                    try:
                        image_array = np.frombuffer(
                            image_bytes,
                            dtype=np.uint8
                        )

                        image = cv2.imdecode(
                            image_array,
                            cv2.IMREAD_COLOR
                        )

                        if image is None:
                            qr_message = (
                                "The image could not be decoded. "
                                "Upload a valid image file."
                            )

                        else:
                            detector = cv2.QRCodeDetector()

                            decoded_text, points, _ = (
                                detector.detectAndDecode(image)
                            )

                            if not decoded_text:
                                qr_message = (
                                    "No readable QR code was found. "
                                    "Try a clear, well-lit QR image."
                                )

                            else:
                                qr_result = decoded_text.strip()

                                parsed_qr = urlparse(qr_result)

                                is_web_url = (
                                    parsed_qr.scheme.lower()
                                    in ("http", "https")
                                    and bool(parsed_qr.hostname)
                                )

                                if is_web_url:
                                    # Analyse the decoded URL.
                                    result = analyse_url(qr_result)

                                    if result["error"]:
                                        qr_message = (
                                            "QR code decoded, but the "
                                            "destination URL is invalid."
                                        )
                                    else:
                                        qr_message = (
                                            "QR code decoded successfully. "
                                            "The destination URL has been "
                                            "analysed below."
                                        )

                                else:
                                    qr_message = (
                                        "QR code decoded successfully. "
                                        "Its contents are displayed below. "
                                        "Only HTTP/HTTPS URLs are analysed."
                                    )

                    except Exception:
                        qr_message = (
                            "An error occurred while reading the QR image. "
                            "Try another PNG, JPG, or WebP image."
                        )

        # ------------------------------------------
        # B. PROCESS NORMAL URL FORM
        # ------------------------------------------

        else:
            submitted_url = request.form.get("url", "")
            result = analyse_url(submitted_url)

    # ----------------------------------------------
    # C. DISPLAY THE PAGE AND RESULTS
    # ----------------------------------------------

    return render_template(
        "scanner.html",
        result=result,
        qr_message=qr_message,
        qr_result=qr_result,
    )
