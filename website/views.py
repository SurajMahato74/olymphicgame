from flask import Blueprint, render_template


views = Blueprint('views', __name__)

@views.route('/')
def home():
    return render_template('/login.html')

@views.route('/login.html')
def login():
    return render_template('login.html')
