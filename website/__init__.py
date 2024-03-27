from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    

    app.config['SECRET_KEY'] = 'Kathmandu@74'
    base_dir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(base_dir, 'website.db')
    app.config["SQLALCHEMY_ECHO"] = True
    app.config["SQLALCHEMY_RECORD_QUERIES"] = True

    db.init_app(app)  # Initialize the SQLAlchemy instance with the app

    with app.app_context():
        try:
            db.create_all()
            print("Database file location:", app.config['SQLALCHEMY_DATABASE_URI'])
        except Exception as exception:
            print("Got the following exception when attempting db.create_all() in __init__.py:", str(exception))
        finally:
            print("db.create_all() in __init__.py was successful - no exceptions were raised")

  


    return app
