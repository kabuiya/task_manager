from dotenv import load_dotenv
import os

load_dotenv()

from flask import Flask
from flask_cors import CORS
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from .models import db, User, CompletedTask, Task
from .views import views_bp


def create_app(config_name='testing'):
    app = Flask(__name__)

    if config_name == 'testing':
        app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@localhost:5433/taskmanangement'

        #app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://root@postgres/circle_test'
    else:
        pass
        # app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@localhost:5433/taskmanangement'

    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    app.register_blueprint(views_bp)
    CORS(app, origins=["http://localhost:5000"])

    admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')
    admin.add_view(ModelView(User, db.session))
    admin.add_view(ModelView(Task, db.session))
    admin.add_view(ModelView(CompletedTask, db.session))

    return app
