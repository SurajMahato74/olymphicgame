import base64
from hashlib import scrypt
from werkzeug.security import generate_password_hash, check_password_hash
from . import db  
from flask import app, url_for
from sqlalchemy.orm import relationship

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    country = db.Column(db.String(50), nullable=True)
    contact_number = db.Column(db.String(20), nullable=True)
    role = db.Column(db.String(20), nullable=True, default='general')

  

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class shows(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    release= db.Column(db.Date, nullable=False)
    language = db.Column(db.String(50), nullable=False)
    duration = db.Column(db.String(20), nullable=False)
    media = db.Column(db.LargeBinary, nullable=False)
    views = db.Column(db.Integer, default=0)
    cover = db.Column(db.String(100), nullable=False)
    @property
    def video_base64(self):
        return base64.b64encode(self.media).decode('utf-8')
    


# Define the UserDetail model
class userdetail(db.Model):
    __tablename__ = 'userdetail'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subscription = db.Column(db.String(255))  # Adjust the length based on your requirements
    favourite = db.Column(db.String(255))  # Adjust the length based on your requirements
    watchlater = db.Column(db.String(255))  # Adjust the length based on your requirements

class Favourite(db.Model):
    __tablename__ = 'favourite'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    show_id = db.Column(db.Integer, db.ForeignKey('shows.id'), nullable=False)  # Corrected table name

    # Define the relationship with the Show model
    show = db.relationship('shows', backref='favourites')

    def __repr__(self):
        return f"<FavouriteShow user_id={self.user_id}, show_id={self.show_id}>"

class Live(db.Model):
    __tablename__ = 'live'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    video = db.Column(db.LargeBinary, nullable=False)


class AdminUser(db.Model):
    __tablename__ = 'AdminUser'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    hash_password = db.Column(db.String(255), nullable=False)
    contact = db.Column(db.Integer)  # Assuming contact is an integer field

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.hash_password, password)

    def __repr__(self):
        return f"<AdminUser {self.username}>"

 