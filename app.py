import os
from flask import Flask, render_template, request, redirect, flash
from flask_script import Manager
from flask_sqlalchemy import SQLAlchemy
from wtforms import ValidationError
from forms import *
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
application = app
bootstrap = Bootstrap(app)

# basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'hard to guess string'
# SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'databases.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///diet.db'

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

db = SQLAlchemy(app)
manager = Manager(app)


class User(UserMixin, db.Model):
	#__tablename__ = 'user'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(50), unique=True, index=True, nullable=False)
	password_hash = db.Column(db.String(128))

	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

	plan = db.relationship('DietPlan', backref='user')
	infos = db.relationship('Info', backref='user')


class DietPlan(db.Model):
	__tablename__ = 'diet'
	id = db.Column(db.Integer, primary_key=True)
	day = db.Column(db.String(50), nullable=False)
	morning_meal = db.Column(db.String(50), nullable=False)
	noon_meal = db.Column(db.String(50), nullable=False)
	evening_meal = db.Column(db.String(50), nullable=False)
	claories_in = db.Column(db.String(50))

	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
	#user = db.relationship('User', backref='diet')

class Info(db.Model):
	__tablename__ = 'info'
	id = db.Column(db.Integer, primary_key=True)
	first_name = db.Column(db.String(50), nullable=False)
	last_name = db.Column(db.String(50), nullable=False)
	weight = db.Column(db.String(50), nullable=False)
	height = db.Column(db.String(50), nullable=False)
	expected_calories = db.Column(db.String(50), nullable=False)

	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


if __name__ == '__main__':
	manager.run()