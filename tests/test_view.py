from datetime import datetime, timedelta

import pytest

from app.models import User, Task, CategoryEnum, PriorityEnum, StatusEnum, CompletedTask
from app.views import hashed_pass





@pytest.fixture
def test_user(db_session):
    hashed_password = hashed_pass('password123')
    user = User(username='testuser', email='test@example.com', password=hashed_password)
    db_session.add(user)
    db_session.commit()
    return user


# getting token
@pytest.fixture
def auth_token(client, test_user):
    response = client.post('/api/v1/login', json={
        'username': test_user.username,
        'password': 'password123'
    })
    return response.json['token']


@pytest.fixture
def create_test_tasks(db_session, test_user):
    task = Task(owner=test_user.id, id=1, title='Test Task', description='Description', priority=PriorityEnum.high,
                status=StatusEnum.pending,
                category=CategoryEnum.work, completion_date=datetime.utcnow() - timedelta(days=1))
    db_session.add(task)
    db_session.commit()
    print(task, 'added task')
    return task


def test_user_registration(client):
    # Test case  1
    response = client.post('/api/v1/register', json={
        'username': 'newuser',
        'email': 'newusert@example.com',
        'password': 'password123'
    })
    assert response.status_code == 201
    assert b"User registered successfully" in response.data
    # test case 2
    response = client.post('/api/v1/register', json={
        'username': '',
        'email': '',
        'password': ''
    })

    assert b"username and email required" in response.data


def test_user_login(client, test_user):
    # Test case 1: Successful login
    response = client.post('/api/v1/login', json={
        'username': test_user.username,
        'password': 'password123'
    })
    print(f"Response status: {response.status_code}")
    print(f"Response content: {response.data}")
    assert response.status_code == 200
    assert b"successfully, logged in" in response.data
    assert 'token' in response.json

    #Test case 2: Invalid credentials
    response = client.post('/api/v1/login', json={
        'username': 'invaliduser',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    assert b"Invalid username or password" in response.data

    #Test case 3: Missing username or password
    response = client.post('/api/v1/login', json={})
    assert response.status_code == 400
    assert b"Username and password are required" in response.data


def test_update_user_details(client, auth_token):
    headers = {'Authorization': f'Bearer {auth_token}'}
    response = client.post('/api/v1/user/update', json={
        'name': 'Updated Name',
        'email': 'updated@example.com'
    }, headers=headers)
    assert response.status_code == 200
    assert b"User details updated successfully" in response.data


#
def test_add_task(client, auth_token):
    headers = {'Authorization': f'Bearer {auth_token}'}
    response = client.post('/api/v1/user/add_task', json={
        'title': 'Test Task',
        'description': 'This is a test task',
        'priority': 'high',
        'category': 'work',
        'completion_date': (datetime.utcnow() + timedelta(days=1)).isoformat()
    }, headers=headers)
    assert response.status_code == 201
    assert b"Task added successfully" in response.data


def test_get_all_tasks(client, auth_token, test_user, db_session, create_test_tasks):
    headers = {'Authorization': f'Bearer {auth_token}'}
    response = client.get('/api/v1/user/get_all_tasks', headers=headers)
    print(f"Response status: {response.status_code}")
    print(f"Response data: {response.data}")

    assert response.status_code == 200



def test_update_task_status(client, auth_token, test_user, create_test_tasks):
    task = create_test_tasks
    headers = {'Authorization': f'Bearer {auth_token}'}

    response = client.put(f'/api/v1/user/update_task_status/{task.id}', headers=headers)
    assert response.status_code == 200
    assert b"Task status updated to in progress" in response.data



def test_get_overdue_tasks(client, auth_token, db_session, test_user):
    headers = {'Authorization': f'Bearer {auth_token}'}
    task = Task(owner=test_user.id, title='Overdue Task', description='Description', priority=PriorityEnum.high,
                category=CategoryEnum.work, completion_date=datetime.utcnow() - timedelta(days=1))
    db_session.add(task)
    db_session.commit()

    response = client.get('/api/v1/user/get_overdue_tasks', headers=headers)
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]['title'] == 'Overdue Task'


def test_get_upcoming_tasks(client, auth_token, db_session, test_user):
    headers = {'Authorization': f'Bearer {auth_token}'}
    task = Task(owner=test_user.id, title='Upcoming Task', description='Description',
                priority=PriorityEnum.high, category=CategoryEnum.work,
                completion_date=datetime.utcnow() + timedelta(hours=12))
    db_session.add(task)
    db_session.commit()

    response = client.get('/api/v1/user/get_upcoming_tasks', headers=headers)
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]['title'] == 'Upcoming Task'



def test_get_task_by_id(client, auth_token, db_session, test_user, create_test_tasks):
    headers = {'Authorization': f'Bearer {auth_token}'}
    task = create_test_tasks
    response = client.get(f'/api/v1/user/get_task/{task.id}', headers=headers)
    assert response.status_code == 200
    assert response.json['title'] == 'Test Task'




def test_update_task(client, auth_token, db_session, test_user):
    headers = {'Authorization': f'Bearer {auth_token}'}
    task = Task(owner=test_user.id, title='Test Task', description='Description', priority=PriorityEnum.high,
                category=CategoryEnum.work, completion_date=(datetime.utcnow() + timedelta(days=1)).isoformat())
    db_session.add(task)
    db_session.commit()

    response = client.put(f'/api/v1/user/update_task/{task.id}', json={
        'title': 'Test Task',
        'description': 'This is a updates task task',
        'priority': 'high',
        'category': 'work',
        'completion_date': (datetime.utcnow() + timedelta(days=1)).isoformat()
    }, headers=headers)
    assert response.status_code == 200
    assert b"Task updated successfully" in response.data


def test_delete_task(client, auth_token, db_session, test_user):
    headers = {'Authorization': f'Bearer {auth_token}'}
    task = Task(owner=test_user.id, title='Test Task', description='Description', priority=PriorityEnum.high,
                category=CategoryEnum.work, completion_date=(datetime.utcnow() + timedelta(days=1)).isoformat())
    db_session.add(task)
    db_session.commit()

    response = client.delete(f'/api/v1/user/delete_task/{task.id}', headers=headers)
    assert response.status_code == 200
    assert b"Task deleted successfully" in response.data


def test_filter_tasks_by_category(client, auth_token, db_session, test_user, create_test_tasks):
    headers = {'Authorization': f'Bearer {auth_token}'}
    response = client.get('/api/v1/tasks/filter/category/work', headers=headers)

    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]['category'] == 'work'


def test_filter_tasks_by_priority(client, auth_token, db_session, test_user):
    headers = {'Authorization': f'Bearer {auth_token}'}
    response = client.get('/api/v1/tasks/filter/priority/high', headers=headers)
    assert response.status_code == 200


#
#
def test_filter_tasks_by_status(client, auth_token, db_session, test_user):
    status = 'pending'
    headers = {'Authorization': f'Bearer {auth_token}'}

    response = client.get(f'/api/v1/tasks/filter/status/{status}', headers=headers)
    assert response.status_code == 200


def test_filter_tasks_by_completion_date(client, auth_token, db_session, test_user):
    headers = {'Authorization': f'Bearer {auth_token}'}
    completion_date = datetime.utcnow().date()

    response = client.get(f'/api/v1/tasks/filter/date/{completion_date.strftime("%Y-%m-%d")}', headers=headers)
    assert response.status_code == 200


def test_complete_task(client, auth_token, db_session, test_user):
    headers = {'Authorization': f'Bearer {auth_token}'}
    task = Task(owner=test_user.id, title='Task to Complete', description='Description', priority=PriorityEnum.high,
                category=CategoryEnum.work)
    db_session.add(task)
    db_session.commit()

    response = client.post(f'/api/v1/tasks/mark_completed/{task.id}', headers=headers)
    assert response.status_code == 200
    assert b"Task completed and moved to Completed table" in response.data


def test_get_completed_tasks(client, auth_token, db_session, test_user):
    headers = {'Authorization': f'Bearer {auth_token}'}
    completed_task = CompletedTask(owner=test_user.id, name='Completed Task')
    db_session.add(completed_task)
    db_session.commit()

    response = client.get('/api/v1/completed-tasks', headers=headers)
    assert response.status_code == 200

    assert response.json[0]['name'] == 'Completed Task'


def test_delete_completed_task(client, auth_token, db_session, test_user):
    headers = {'Authorization': f'Bearer {auth_token}'}
    completed_task = CompletedTask(owner=test_user.id, name='Completed Task')
    db_session.add(completed_task)
    db_session.commit()

    response = client.delete(f'/api/v1/task/delete_completed/{completed_task.id}', headers=headers)
    assert response.status_code == 200
    assert b"Completed task deleted successfully" in response.data


def test_delete_all_completed_tasks(client, auth_token, db_session, test_user):
    headers = {'Authorization': f'Bearer {auth_token}'}
    completed_task1 = CompletedTask(owner=test_user.id, name='Completed Task 1')
    completed_task2 = CompletedTask(owner=test_user.id, name='Completed Task 2')
    db_session.add_all([completed_task1, completed_task2])
    db_session.commit()

    response = client.delete('/api/v1/tasks/delete_all_completed/', headers=headers)
    assert response.status_code == 200
    assert b"All completed tasks deleted successfully" in response.data


def test_filter_tasks_by_category_and_priority(client, auth_token, db_session, test_user):
    headers = {'Authorization': f'Bearer {auth_token}'}

    response = client.get('/api/v1/tasks/filter/category/work/priority/high', headers=headers)
    assert response.status_code == 200


def test_filter_tasks_by_category_and_status(client, auth_token, db_session, test_user):
    headers = {'Authorization': f'Bearer {auth_token}'}
    response = client.get(f'/api/v1/tasks/filter/category/work/status/pending',
                          headers=headers)
    assert response.status_code == 200


def test_filter_tasks_by_category_and_completion_date(client, auth_token, db_session, test_user):
    headers = {'Authorization': f'Bearer {auth_token}'}
    completion_date = datetime.utcnow().date()
    task = Task(owner=test_user.id, title='Today Work Task', description='Description', priority=PriorityEnum.medium,
                status=StatusEnum.pending,
                category=CategoryEnum.study, completion_date=completion_date)
    db_session.add(task)
    db_session.commit()

    response = client.get(
        f'/api/v1/tasks/filter/category/{task.category.name}/date/{completion_date.strftime("%Y-%m-%d")}',
        headers=headers)
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]['title'] == 'Today Work Task'
