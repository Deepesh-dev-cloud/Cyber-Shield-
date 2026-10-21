from datetime import datetime

from app.database.db import db


class LoginAttempt(db.Model):

    __tablename__ = "login_attempts"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        nullable=False
    )

    ip_address = db.Column(
        db.String(45),
        nullable=False
    )

    login_success = db.Column(
        db.Boolean,
        nullable=False
    )

    typing_speed = db.Column(
        db.Float,
        nullable=True
    )

    average_key_interval = db.Column(
        db.Float,
        nullable=True
    )

    typing_variation = db.Column(
        db.Float,
        nullable=True
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    def __repr__(self):

        return (
            f"<LoginAttempt "
            f"username={self.username} "
            f"ip={self.ip_address} "
            f"success={self.login_success} "
            f"wpm={self.typing_speed} "
            f"key_interval={self.average_key_interval} "
            f"variation={self.typing_variation}>"
        )