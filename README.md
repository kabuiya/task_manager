
# Task Manager API
(CRUD)
The Task Manager API is a Flask-based CRUD application designed to provide users with a platform to manage their tasks efficiently. It offers various functionalities such as user registration, task creation, task filtering, task completion, and more.
## Features

- **User Registration**: Users can register their accounts with unique usernames and passwords.
- **User Authentication**: Authentication is handled using JSON Web Tokens (JWT) to secure endpoints.
- **Task Management**: Users can create, update, delete, and view their tasks.
- **Task Filtering**: Tasks can be filtered based on category, priority, status, and completion date.
- **Task Completion**: Users can mark tasks as completed and view completed tasks.

### Technologies used:
- Python, Flask RESTful
- Database: PostgreSQL (chosen based on project requirements)
  Authentication: JSON Web Tokens (JWT) for authentication and authorization
  Testing: tests written with pytest
  Continuous Integration: Integrated with CircleCI
  Continuous Coverage: Utilizes coverage tools to measure test coverage (coveralls)

## Endpoints

### User Management

- `POST /api/v1/register`: Register a new user.
- `POST /api/v1/login`: Log in an existing user.
- `POST /api/v1/user/update`: Update user details.
- `DELETE /api/v1/user/delete`: Delete user account.

### Task Management

- `POST /api/v1/user/add_task`: Add a new task for the authenticated user.
- `GET /api/v1/user/get_all_tasks`: Get all tasks for the authenticated user.
- `GET /api/v1/user/get_pending_tasks`: Get tasks passed their completion date for the authenticated user.
- `GET /api/v1/user/get_upcoming_tasks`: Get tasks due within the next 24 hours for the authenticated user.
- `GET /api/v1/user/get_task/<int:task_id>`: Get a specific task by ID for the authenticated user.
- `UPDATE /api/v1/user/update_task/<int:task_id>`: Update a specific task by ID for the authenticated user.
- `DELETE /api/v1/user/delete_task/<int:task_id>`: Delete a specific task by ID for the authenticated user.
- `POST /api/v1/tasks/mark_completed/<int:task_id>`: Mark a task as completed and move it to the completed tasks table.
- `GET /api/v1/completed-tasks`: Get all completed tasks for the authenticated user.
- `DELETE /api/v1/tasks/delete_completed/<int:task_id>`: Delete a completed task by ID for the authenticated user.
- `DELETE /api/v1/tasks/delete_all_completed/`: Delete all completed tasks for the authenticated user.

### Task Filtering

- `GET /api/v1/tasks/filter/category/<category_name>`: Filter tasks by category.
- `GET /api/v1/tasks/filter/priority/<priority_name>`: Filter tasks by priority.
- `GET /api/v1/tasks/filter/status/<status_name>`: Filter tasks by status.
- `GET /api/v1/tasks/filter/date/<completion_date>`: Filter tasks by completion date.
- `GET /api/v1/tasks/filter/category/<category_name>/priority/<priority_name>`: Filter tasks by category and priority.
- `GET /api/v1/tasks/filter/category/<category_name>/status/<status_name>`: Filter tasks by category and status.
- `GET /api/v1/tasks/filter/category/<category_name>/date/<completion_date>`: Filter tasks by category and completion date.

## Setup

1. Clone the repository: `git clone https://github.com/yourusername/task-manager-api.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Set up the database URI in the configuration.
4. Run the Flask application: `python run.py`

