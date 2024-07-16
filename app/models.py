from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import enum

db = SQLAlchemy()


class PriorityEnum(enum.Enum):
    high = 'high'
    medium = 'medium'
    low = 'low'


class StatusEnum(enum.Enum):
    progress = 'in progress'
    pending = 'pending'


class CategoryEnum(enum.Enum):
    personal = 'personal'
    work = 'work'
    shopping = 'shopping'
    study = 'study'


class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return self.username


class Task(db.Model):
    __tablename__ = 'task'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    owner = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    priority = db.Column(db.Enum(PriorityEnum), nullable=False)
    status = db.Column(db.Enum(StatusEnum), nullable=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    completion_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.Column(db.Enum(CategoryEnum),
                         nullable=False)  # Using Enum for categoryshing a one-to-many relationship

    def __repr__(self):
        return f'<Task {self.title}>'


class CompletedTask(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    owner = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
