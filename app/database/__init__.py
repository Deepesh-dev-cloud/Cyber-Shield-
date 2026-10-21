from flask import Flask
from app.database.db import db 

def create_app():
    app = Flask(__name__)

    app.config["SQLALCHEMY_DATABSE_URL"] = "sqlite:///cybersheild.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    @app.route("/")
    def home():
        return "Cyber Shield Backend ie running!"

    with app.app_context():
        db.create_all()
        
    return app