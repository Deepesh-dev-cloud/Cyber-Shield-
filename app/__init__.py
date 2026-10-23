
from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

from app.database.db import db
from app.database.models import User
from app.database.login_attempt import LoginAttempt

from app.auth.routes import auth

from app.link_analyzer import link_analyzer
from app.link_analyzer import routes as link_analyzer_routes

# Cybersecurity News & Updates
from app.news import news
from app.news import routes as news_routes


def create_app():
    app = Flask(__name__)

    # Trust one configured reverse proxy for client IP and HTTPS scheme.
    # Verify the proxy chain before enabling this in production.
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1
    )

    # Database configuration
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cybershield.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize database
    db.init_app(app)

    # Register login and registration routes
    app.register_blueprint(auth)

    # Register Link / QR Analyser
    app.register_blueprint(link_analyzer)

    # Register Cybersecurity News module
    app.register_blueprint(news)

    # Home route
    @app.route("/")
    def home():
        return render_template("home.html")

    # Create database tables
    with app.app_context():
        db.create_all()

    return app
