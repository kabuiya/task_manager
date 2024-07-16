from datetime import datetime, timedelta
from functools import wraps
from sqlalchemy import func

import bcrypt
import jwt
from flask import request, jsonify, current_app
from flask import Blueprint

from app.models import User, db, Task, CompletedTask, PriorityEnum, StatusEnum, CategoryEnum

views_bp = Blueprint('views', __name__)


def token_required(funct):
    """
        A decorator function to ensure that a valid JWT token is present in the request headers.

        This decorator extracts the JWT token from the 'Authorization' header,
        decodes and verifies it, and then passes the extracted user_id to the
        decorated function.

        Args:
            funct (callable): The function to be decorated.

        Returns:
            callable: The wrapped function.

        Raises:
            jwt.ExpiredSignatureError: If the token has expired.
            jwt.InvalidTokenError: If the token is invalid.

        Returns:
            Response: JSON response indicating the success or failure of the token validation.

        """

    @wraps(funct)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        print(token)
        if not token:
            return jsonify({'message': 'Missing authorization token'}), 401

        try:
            token = token.split()[1]
            print(token)
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = payload.get('user_id')  # Extract user_id from the JWT payload
            user_name = payload.get('username')
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        if user_id is None or user_name is None:
            return jsonify({'message': 'Unauthorized access'}), 401
        return funct(user_id, *args, **kwargs)

    return wrapper


@views_bp.route("/api/v1/register", methods=['POST'])
def user_registration():
    data = request.get_json()
    if data['username'] != '' and data['email'] != '' and data['password'] != '':
        hashed_password = hashed_pass(data['password'])
        print(hashed_password, 'stored password')
        truncated_username = data['username'][:120]
        new_user = User(username=truncated_username, email=data['email'], password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            return jsonify({"message": "User registered successfully"}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500
    return jsonify({'details': {"details": "username and email required"}})


def hashed_pass(plaintext_password):
    """
        Hashes the given plaintext password using bcrypt.

        This func takes a plaintext password as input, generates a salt using bcrypt,
        and then hashes the password using the salt. The resulting hashed password is returned.

        Args:
            plaintext_password (str): The plaintext password to be hashed.

        Returns:
            bytes: The hashed password as a bytes object.

        """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(plaintext_password.encode('utf-8'), salt)

    return hashed_password


@views_bp.route("/api/v1/login", methods=['POST'])
def user_login():
    try:
        data = request.get_json()
        if 'username' in data and 'password' in data:
            username = data['username']
            password = data['password']
            user = User.query.filter_by(username=username).first()
            if user and check_password(password, user.password):
                token = jwt.encode(
                    {'user_id': user.id, 'username': username,
                     'exp': datetime.utcnow() + timedelta(minutes=30)},
                    current_app.config['SECRET_KEY'])
                #return jsonify({'message': {'success': 'successfully, logged in', 'token': token}}), 200
                return jsonify({'success': 'successfully, logged in', 'token': token}), 200
            else:
                return jsonify({"error": "Invalid username or password"}), 401
        else:
            return jsonify({"error": "Username and password are required"}), 400

    except Exception as e:
        import traceback
        return jsonify({"error": "An internal error occurred"}), 500


def check_password(passwd, hashed_password_hex):
    hashed_password_bytes = bytes.fromhex(hashed_password_hex[2:])
    return bcrypt.checkpw(passwd.encode('utf-8'), hashed_password_bytes)


@views_bp.route("/api/v1/user/update", methods=['POST'])
@token_required
def update_user_details(user_id):
    data = request.get_json()
    new_name = data.get('name')
    new_email = data.get('email')

    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    if new_name:
        user.name = new_name
    if new_email:
        user.email = new_email

    try:
        db.session.commit()
        return jsonify({"message": "User details updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/user/delete", methods=['DELETE'])
@token_required
def delete_user_account(user_id):
    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User account deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/user/add_task", methods=['POST'])
@token_required
def add_task_to_user(user_id):
    task_data = request.get_json()
    try:
        try:
            priority = PriorityEnum[task_data['priority']]
            category = CategoryEnum[task_data['category']]
        except KeyError as e:
            return jsonify({"error": f"Invalid value for {e.args[0]}"})
        new_task = Task(
            owner=user_id,
            category=category,
            priority=priority,
            status="pending",
            title=task_data.get('title'),
            description=task_data.get('description'),
            completion_date=task_data.get('completion_date')
        )
        db.session.add(new_task)
        db.session.commit()
        return jsonify({"message": "Task added successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500  #


@views_bp.route("/api/v1/user/get_all_tasks", methods=['GET'])
@token_required
def get_all_tasks_for_user(user_id):
    try:

        tasks = Task.query.filter_by(owner=user_id).all()
        print(tasks, 'user tasks')
        serialized_tasks = [
            {"id": task.id, "owner": task.owner, "status": task.status.name, "category": task.category.name,
             "priority": task.priority.name, "title": task.title, "description": task.description,
             "completion_date": task.completion_date.strftime("%Y-%m-%d %H:%M:%S"),
             "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S"), }
            for task in tasks]
        print(serialized_tasks)
        return jsonify(serialized_tasks), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/user/update_task_status/<int:task_id>", methods=['put'])
@token_required
def update_task_status(user_id, task_id):
    try:
        task = Task.query.filter_by(id=task_id, owner=user_id).first()
        print(task.status, 'task status')
        if not task:
            return jsonify({"error": "Task not found"}), 404

        if task.status == StatusEnum.pending:
            print('pending')
            task.status = StatusEnum.progress
            db.session.commit()
            print('status after updatinng', task.status)
            return jsonify({"message": "Task status updated to in progress"}), 200
        return jsonify({"error": "Task is not in pending status"}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/user/get_overdue_tasks", methods=['GET'])
@token_required
def get_tasks_passed_completion_date_for_user(user_id):
    try:
        current_datetime = datetime.utcnow()
        tasks_passed_completion_date = Task.query.filter(Task.owner == user_id,
                                                         Task.completion_date <= current_datetime).all()
        serialized_tasks = []
        for task in tasks_passed_completion_date:
            serialized_task = {
                "id": task.id,
                "owner": task.owner,
                "category": task.category.name,
                "priority": task.priority.value,
                "title": task.title,
                "description": task.description,
                "completion_date": task.completion_date.strftime("%Y-%m-%d %H:%M:%S") if task.completion_date else None,
                "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            serialized_tasks.append(serialized_task)

        return jsonify(serialized_tasks), 200
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


@views_bp.route("/api/v1/user/get_upcoming_tasks", methods=['GET'])
@token_required
def get_tasks_within_next_24_hours(user_id):
    try:
        current_datetime = datetime.utcnow()
        end_datetime = current_datetime + timedelta(hours=24)
        tasks_within_next_24_hours = Task.query.filter(Task.owner == user_id, Task.completion_date >= current_datetime,
                                                       Task.completion_date <= end_datetime).all()

        serialized_upcomingTasks = []
        for task in tasks_within_next_24_hours:
            serialized_upcomingTask = {
                "id": task.id,
                "owner": task.owner,
                "category": task.category.name,  # Assuming task.category is an Enum with a 'name' attribute
                "priority": task.priority.value,  # Assuming task.priority is an Enum with a 'value' attribute
                "title": task.title,
                "description": task.description,
                "completion_date": task.completion_date.strftime("%Y-%m-%d %H:%M:%S") if task.completion_date else None,
                "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            serialized_upcomingTasks.append(serialized_upcomingTask)

        return jsonify(serialized_upcomingTasks), 200
    except Exception as e:
        return None


@views_bp.route("/api/v1/user/get_task/<int:task_id>", methods=['GET'])
@token_required
def get_task_by_id(user_id, task_id):
    try:
        task = Task.query.filter_by(id=task_id, owner=user_id).first()
        if task:
            serialized_task = {"id": task.id, "owner": task.owner, "category": task.category.name,
                               "priority": task.priority.name, "title": task.title, "description": task.description,
                               "completion_date": task.completion_date.strftime("%Y-%m-%d %H:%M:%S"),
                               "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                               }
            return jsonify(serialized_task), 200
        else:
            return jsonify({"error": "Task not found or unauthorized"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/user/update_task/<int:task_id>", methods=['PUT'])
@token_required
def update_task(user_id, task_id):
    try:
        task = Task.query.filter_by(id=task_id, owner=user_id).first()
        if task:
            updated_data = request.get_json()
            for key, value in updated_data.items():
                setattr(task, key, value)
            db.session.commit()
            return jsonify({"message": "Task updated successfully"}), 200
        else:

            return jsonify({"error": "Task not found or unauthorized"}), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/user/delete_task/<int:task_id>", methods=['DELETE'])
@token_required
def delete_task(user_id, task_id):
    try:
        task = Task.query.filter_by(id=task_id, owner=user_id).first()
        if task:
            db.session.delete(task)
            db.session.commit()
            return jsonify({"message": "Task deleted successfully"}), 200
        else:
            return jsonify({"error": "Task not found or unauthorized"}), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


#
#
# # filtering
@views_bp.route("/api/v1/tasks/filter/category/<category_name>", methods=['GET'])
@token_required
def filter_user_tasks_by_category(user_id, category_name):
    try:
        user_category_tasks = Task.query.filter(
            Task.owner == user_id,
            Task.category == CategoryEnum[category_name]
        ).all()

        serialized_tasks = [{
            "id": task.id,
            "owner": task.owner,
            "category": task.category.name,
            "priority": task.priority.name,
            "status": task.status.name,
            "title": task.title,
            "description": task.description,
            "completion_date": task.completion_date.strftime("%Y-%m-%d %H:%M:%S") if task.completion_date else None,
            "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        } for task in user_category_tasks]

        return jsonify(serialized_tasks), 200
    except KeyError:
        return jsonify({"error": f"Invalid category: {category_name}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/tasks/filter/priority/<priority_name>", methods=['GET'])
@token_required
def filter_user_tasks_by_priority(user_id, priority_name):
    try:
        user_priority_tasks = Task.query.filter(Task.owner == user_id, Task.priority == priority_name).all()
        serialized_tasks = [{
            "id": task.id,
            "owner": task.owner,
            "category": task.category.name,
            "priority": task.priority.name,
            "title": task.title,
            "description": task.description,
            "completion_date": task.completion_date.strftime("%Y-%m-%d %H:%M:%S"),
            "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S")
        } for task in user_priority_tasks]
        return jsonify(serialized_tasks), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/tasks/filter/status/<status_name>", methods=['GET'])
@token_required
def filter_user_tasks_by_status(user_id, status_name):
    try:
        user_priority_tasks = Task.query.filter(Task.owner == user_id, Task.status == status_name).all()
        serialized_tasks = [{
            "id": task.id,
            "owner": task.owner,
            "category": task.category.name,
            "priority": task.priority.name,
            "title": task.title,
            "description": task.description,
            "completion_date": task.completion_date.strftime("%Y-%m-%d %H:%M:%S"),
            "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S")
        } for task in user_priority_tasks]
        return jsonify(serialized_tasks), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/tasks/filter/date/<date>", methods=['GET'])
@token_required
def filter_user_tasks_by_completion_date(user_id, date):
    try:
        date = date.strip()
        filter_date = datetime.strptime(date, '%Y-%m-%d').date()
        tasks = Task.query.filter(
            Task.owner == user_id,
            func.date(Task.completion_date) == filter_date
        ).all()
        serialized_tasks = [{
            "id": task.id,
            "owner": task.owner,
            "category": task.category.name,
            "priority": task.priority.name,
            "title": task.title,
            "description": task.description,
            "completion_date": task.completion_date.strftime("%Y-%m-%d %H:%M:%S"),
            "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S")
        } for task in tasks]

        return jsonify(serialized_tasks), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/tasks/mark_completed/<int:task_id>", methods=['POST'])
@token_required
def complete_task(current_user_id, task_id):
    try:
        task = Task.query.filter_by(id=task_id, owner=current_user_id).first()
        if not task:
            return jsonify({"error": "Task not found or does not belong to the authenticated user"}), 404
        completed_task = CompletedTask(
            id=task.id,
            owner=task.owner,
            name=task.title,
        )
        db.session.add(completed_task)
        db.session.delete(task)
        db.session.commit()

        return jsonify({"message": "Task completed and moved to Completed table"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/completed-tasks", methods=['GET'])
@token_required
def get_completed_tasks(user_id):
    try:
        user_completed_tasks = CompletedTask.query.filter_by(owner=user_id).all()
        serialized_tasks = [{
            "id": task.id,
            "name": task.name,
            "owner": task.owner
        } for task in user_completed_tasks]
        return jsonify(serialized_tasks), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/task/delete_completed/<int:task_id>", methods=['DELETE'])
@token_required
def delete_completed_task(user_id, task_id):
    try:
        completed_task = CompletedTask.query.filter_by(id=task_id, owner=user_id).first()

        if not completed_task:
            return jsonify({"error": "Completed task not found or does not belong to the authenticated user"}), 404
        db.session.delete(completed_task)
        db.session.commit()

        return jsonify({"message": "Completed task deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/tasks/delete_all_completed/", methods=['DELETE'])
@token_required
def delete_all_completed_tasks(current_user_id):
    try:
        completed_tasks = CompletedTask.query.filter_by(owner=current_user_id).all()

        if not completed_tasks:
            return jsonify({"error": "No completed tasks found for the authenticated user"}), 404

        for completed_task in completed_tasks:
            db.session.delete(completed_task)
        db.session.commit()

        return jsonify({"message": "All completed tasks deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


#filter by category and priority
@views_bp.route("/api/v1/tasks/filter/category/<category_name>/priority/<priority_name>", methods=['GET'])
@token_required
def filter_tasks_by_category_and_priority(user_id, category_name, priority_name):
    try:
        try:
            category = CategoryEnum(category_name.lower())
            priority = PriorityEnum(priority_name.lower())
        except ValueError:
            return jsonify({"error": "Invalid category or priority"}), 400

        user_tasks = Task.query.filter(
            Task.owner == user_id,
            Task.category == category,
            Task.priority == priority
        ).all()
        serialized_tasks = [{
            "id": task.id,
            "category": task.category.name,
            "priority": task.priority.name,
            "title": task.title,
            "description": task.description,
            "completion_date": task.completion_date.strftime("%Y-%m-%d %H:%M:%S"),
            "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S")
        } for task in user_tasks]
        return jsonify(serialized_tasks), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/tasks/filter/category/<category_name>/status/<status_name>", methods=['GET'])
@token_required
def filter_tasks_by_category_and_status(user_id, category_name, status_name):
    try:
        try:
            category = CategoryEnum(category_name.lower())
            status = StatusEnum(status_name.lower())
        except ValueError:
            return jsonify({"error": "Invalid category or priority"}), 400

        user_tasks = Task.query.filter(
            Task.owner == user_id,
            Task.category == category,
            Task.status == status
        ).all()
        serialized_tasks = [{
            "id": task.id,
            "category": task.category.name,
            "priority": task.priority.name,
            "title": task.title,
            "description": task.description,
            "completion_date": task.completion_date.strftime("%Y-%m-%d %H:%M:%S"),
            "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S")
        } for task in user_tasks]
        return jsonify(serialized_tasks), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@views_bp.route("/api/v1/tasks/filter/category/<category_name>/date/<completion_date>", methods=['GET'])
@token_required
def filter_tasks_by_category_and_completion_date(user_id, category_name, completion_date):
    try:
        completion_date = datetime.strptime(completion_date, "%Y-%m-%d").date()
        try:
            category = CategoryEnum(category_name.lower())
            print(category)

        except ValueError:
            return jsonify({"error": "Invalid category or priority"}), 400

        user_tasks = Task.query.filter(
            Task.owner == user_id,
            Task.category == category,
            func.DATE(Task.completion_date) == completion_date
        ).all()

        serialized_tasks = [{
            "id": task.id,
            "category": task.category.name,
            "completion_date": task.completion_date.strftime("%Y-%m-%d %H:%M:%S"),
            "title": task.title,
            "description": task.description,
            "priority": task.priority.name,
            "created_at": task.created_at.strftime("%Y-%m-%d %H:%M:%S")
        } for task in user_tasks]

        return jsonify(serialized_tasks), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

#
