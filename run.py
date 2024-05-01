

from flask import Flask

from flask_cors import CORS
from views.views import views_bp
from model.models import db, User, Category, CompletedTask, Task
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@localhost:5433/taskmanangement'
app.config['SECRET_KEY'] = 'hytersgasdass'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.register_blueprint(views_bp)
db.init_app(app)
CORS(app, origins=["http: // localhost: 5000"])

admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Category, db.session))
admin.add_view(ModelView(Task, db.session))
admin.add_view(ModelView(CompletedTask, db.session))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)


