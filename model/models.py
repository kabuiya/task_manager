from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


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
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    priority = db.Column(db.String(50), unique=True, nullable=False)
    status = db.Column(db.String(50), unique=True, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    completion_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.relationship('Category', backref='tasks')  # Establishing a one-to-many relationship

    def __repr__(self):
        return f'<Task {self.title}>'


class Category(db.Model):
    __tablename__ = 'category'

    name = db.Column(db.String(50), unique=True, nullable=False)
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    def __repr__(self):
        return f'<Category {self.name}>'


class CompletedTask(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    owner = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
