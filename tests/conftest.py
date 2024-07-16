

import pytest
from app import create_app, db
from sqlalchemy.orm import scoped_session, sessionmaker


@pytest.fixture(scope='function')
def app():
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture(scope='function')
def client(app):
    return app.test_client()


@pytest.fixture(scope='function')
def db_session(app):
    with app.app_context():
        connection = db.engine.connect()
        session = scoped_session(sessionmaker(bind=connection))
        db.session = session
        yield session
        session.close()
        connection.close()


@pytest.fixture(autouse=True)
def cleanup(db_session):
    yield
    db_session.rollback()
    db_session.close()
