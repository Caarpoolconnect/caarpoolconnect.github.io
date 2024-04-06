# Adrik, Install libraries first---- pip install --user flask flask_sqlalchemy flask_bcrypt flask_login Flask-WTF email_validator


# Import necessary libraries
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, DateTimeField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from datetime import datetime
import os

# Initialize the Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///carpoolconnect.db'



# Initialize Flask extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

with app.app_context():
    db.create_all()
# Define database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    rides_offered = db.relationship('RideOffer', backref='driver', lazy=True)

class RideOffer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    destination = db.Column(db.String(100), nullable=False)
    departure_time = db.Column(db.DateTime, nullable=False)
    seats_available = db.Column(db.Integer, nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Define form classes
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RideOfferForm(FlaskForm):
    destination = StringField('Destination', validators=[DataRequired()])
    departure_time = DateTimeField('Departure Time', format='%Y-%m-%d %H:%M', default=datetime.now, validators=[DataRequired()])
    seats_available = IntegerField('Seats Available', validators=[DataRequired()])
    submit = SubmitField('Offer Ride')

class RideSearchForm(FlaskForm):
    departure = StringField('Departure', validators=[DataRequired()])
    destination = StringField('Destination', validators=[DataRequired()])
    desired_departure_time = DateTimeField('Desired Departure Time', format='%Y-%m-%d %H:%M', validators=[DataRequired()])
    submit = SubmitField('Search for Ride')

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define routes
@app.route('/')
def index():
    return render_template('index.html')

 

@app.route('/dashboard')
@login_required
def dashboard():
    rides = RideOffer.query.all()
    form = RideOfferForm()  # Make sure to initialize the form here
    return render_template('dashboard.html', rides=rides, form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/offer_ride', methods=['GET', 'POST'])
@login_required
def offer_ride():
    form = RideOfferForm()
    if form.validate_on_submit():
        ride = RideOffer(destination=form.destination.data, departure_time=form.departure_time.data,
                         seats_available=form.seats_available.data, driver=current_user)
        db.session.add(ride)
        db.session.commit()
        flash('Your ride offer has been created!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('offer_ride.html', title='Offer Ride', form=form)

@app.route('/search_ride', methods=['GET', 'POST'])
def search_ride():
    form = RideSearchForm()
    if form.validate_on_submit():
        # This is a placeholder for actual search logic
        flash('Search feature not implemented yet.', 'info')
        return redirect(url_for('index'))
    return render_template('search_ride.html', title='Search for a Ride', form=form)

@app.route('/some_route', methods=['GET', 'POST'])
def some_route():
    form = SomeForm()  # Initialize your form
    if form.validate_on_submit():
        # Process the form data
        return redirect(url_for('some_other_route'))
    return render_template('template_name.html', form=form)

# Run the Flask app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
