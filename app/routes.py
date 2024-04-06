from flask import render_template, url_for, flash, redirect, request
from flask_login import login_user, current_user, logout_user, login_required
from app import app, db, bcrypt
from app.models import User, RideOffer
from app.forms import RegistrationForm, LoginForm, RideOfferForm, RideSearchForm

@app.route('/dashboard')
@login_required
def dashboard():
    rides = RideOffer.query.filter_by()  # Add any filters you need, or leave blank to get all
    return render_template('dashboard.html', rides=rides)

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
    return redirect(url_for('dashboard'))


def index():
    return render_template('index.html')

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
    return redirect(url_for('dashboard'))

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
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/offer_ride', methods=['GET', 'POST'])
@login_required
def offer_ride():
    form = RideOfferForm()
    if form.validate_on_submit():
        ride = RideOffer(destination=form.destination.data, departure_time=form.departure_time.data, seats_available=form.seats_available.data, driver_id=current_user.id)
        db.session.add(ride)
        db.session.commit()
        flash('Your ride offer has been created!', 'success')
        return redirect(url_for('index'))
    return render_template('offer_ride.html', form=form)

@app.route('/search_ride', methods=['GET', 'POST'])
def search_ride():
    form = RideSearchForm()
    if form.validate_on_submit():
        # Implement search logic here
        flash('Search feature not implemented yet.', 'info')
        return redirect(url_for('index'))
    return render_template('search_ride.html', form=form)
