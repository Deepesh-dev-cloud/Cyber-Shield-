
from flask import Flask, render_template

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

    # Database configuration
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cybershield.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize database
    db.init_app(app)

    # Register existing login system
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
