from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, DateTimeField
from wtforms.validators import DataRequired, Length, Email, EqualTo

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
    departure_time = DateTimeField('Departure Time', format='%Y-%m-%d %H:%M', validators=[DataRequired()])
    seats_available = IntegerField('Seats Available', validators=[DataRequired()])
    submit = SubmitField('Offer Ride')

class RideSearchForm(FlaskForm):
    departure = StringField('Departure', validators=[DataRequired()])
    destination = StringField('Destination', validators=[DataRequired()])
    desired_departure_time = DateTimeField('Desired Departure Time', format='%Y-%m-%d %H:%M', validators=[DataRequired()])
    submit = SubmitField('Search for Ride')
