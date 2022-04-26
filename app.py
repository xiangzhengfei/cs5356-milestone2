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


@app.route('/', methods=['POST', 'GET'])
@login_required
def index():
	status = current_user.is_active
	if status:
		if request.method == "POST" and request.form.get("add_info"): 
			f_name = request.form['f_name']
			l_name = request.form['l_name']
			weight = request.form['weight']
			height = request.form['height']
			exp_calories = request.form['calories']
			new_info = Info(first_name=f_name, last_name=l_name, weight=weight, 
				height=height, expected_calories=exp_calories, user=current_user)
			try:
				db.session.add(new_info)
				db.session.commit()
				return redirect('/')
			except:
				return "There was an error adding the user!"
		else:
			diets = DietPlan.query.filter_by(user=current_user)
			infos = Info.query.filter_by(user=current_user)
			return render_template('main.html', diets=diets, infos=infos)
	else:
		return redirect('/login')
	
@app.route('/signup', methods=['GET', 'POST'])
def signup():
	form = SignupForm()
	if form.validate_on_submit():
		new_user = User(username=form.username.data, password=form.password.data)
		if User.query.filter_by(username=form.username.data).first():
			flash('Username already in use, try another one.')
		else:
			try:
				db.session.add(new_user)
				db.session.commit()
				return redirect('/login')
			except:
				return "There was an error registrating the user!"

	return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user)
			return redirect('/')
		flash('Wrong username or password')
	return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logged out.')
	return redirect('/login')


@app.route('/changepassword/<int:id>', methods=['POST', 'GET'])
def changepassword(id):
	user_to_update = User.query.get_or_404(id)
	if request.method == "POST":
		user_to_update.password = request.form['password']
		db.session.commit()
		flash('Please log in again since you have changed your password.')
		return redirect('/logout')
	return render_template('changepassword.html', user_to_update=user_to_update)


@app.route('/delete_info/<int:id>')
def delete_info(id):
    plan_to_delete = Info.query.get_or_404(id)
    try:
        db.session.delete(plan_to_delete)
        db.session.commit()
        return redirect('/')
    except:
        return "There was an error deleting the info!"

if __name__ == '__main__':
	manager.run()