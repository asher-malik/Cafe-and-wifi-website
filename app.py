import hashlib
import os
from functools import wraps
from flask_gravatar import Gravatar
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask_ckeditor import CKEditor
from flask_dance.contrib.google import make_google_blueprint, google
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap5
from flask_migrate import Migrate
from flask_wtf import FlaskForm, CSRFProtect, RecaptchaField
from wtforms import StringField, SubmitField, Form, PasswordField, validators, EmailField
from flask_ckeditor import CKEditorField
from wtforms.validators import DataRequired, Length

app = Flask(__name__)
csrf = CSRFProtect(app)
ckeditor = CKEditor(app)

app.config['CKEDITOR_PKG_TYPE'] = 'standard'
app.secret_key = 'SonyL1/123Heyzxyzsyn'

GOOGLE_CLIENT_ID = '606238041999-qj5dqr7tjahia7pk0ogvliqrvn3dgl17.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

app.config['RECAPTCHA_PUBLIC_KEY'] = '6LfpP1kpAAAAAHOzELguW7msMWfI4tIQQ0i0Ego-'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LfpP1kpAAAAADHMK9pcfoSv-aXqeaP9VCWf6ETl'

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

app.config['MAIL_DEFAULT_SENDER'] = "noreply@flask.com"
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEBUG'] = True
app.config['MAIL_USERNAME'] = '12345ashermalik@gmail.com'
app.config['MAIL_PASSWORD'] = 'eudpegvgpqmxbrmf'

app.config.update(dict(
    MAIL_DEFAULT_SENDER="noreply@flask.com",
    DEBUG = True,
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 587,
    MAIL_USE_TLS = True,
    MAIL_USE_SSL = False,
    MAIL_USERNAME = '12345ashermalik@gmail.com',
    MAIL_PASSWORD = 'eudpegvgpqmxbrmf',
))

global google_check
google_check = 0

mail = Mail(app)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
bootstrap = Bootstrap5(app)

migrate = Migrate(app, db)

google_bp = make_google_blueprint(client_id=GOOGLE_CLIENT_ID,
                                  client_secret=GOOGLE_CLIENT_SECRET,
                                  reprompt_consent=True,
                                  scope=["https://www.googleapis.com/auth/userinfo.email"],
                                  )

app.register_blueprint(google_bp, url_prefix="/login")

def hash_password(password):
    # Convert the password to bytes
    password_bytes = password.encode('utf-8')

    # Create a new SHA-256 hash object
    sha256 = hashlib.sha256()

    # Update the hash object with the password bytes
    sha256.update(password_bytes)

    # Get the hexadecimal representation of the hashed password
    hashed_password = sha256.hexdigest()

    return hashed_password

def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return serializer.dumps(email, salt='email-verification')

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = serializer.loads(
            token, salt='email-verification', max_age=expiration
        )
        return email
    except Exception:
        return False

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config["MAIL_DEFAULT_SENDER"],
    )
    mail.send(msg)

def logout_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            flash("You are already authenticated.", "info")
            return redirect(url_for("home"))
        return func(*args, **kwargs)

    return decorated_function

def admin_required(view_func):
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        # Check if the current user is authenticated and has ID equal to 1
        if not current_user.is_authenticated or current_user.id != 1:
            # Redirect or abort, depending on your requirements
            return redirect(url_for('home'))  # Redirect to login page
            # Or use abort(403) to show a forbidden error page

        # If the user is authenticated and has the required ID, proceed to the view
        return view_func(*args, **kwargs)

    return decorated_view

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=True)
    verified = db.Column(db.Boolean, default=False)
    user_comment = db.relationship('CommentReviews', backref='user', cascade="all, delete-orphan", lazy=True)

class Cafes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    map_url = db.Column(db.String, nullable=False)
    img_url = db.Column(db.String, nullable=False)
    location = db.Column(db.String, nullable=False)
    has_sockets = db.Column(db.Boolean, nullable=False)
    has_toilet = db.Column(db.Boolean, nullable=False)
    has_wifi = db.Column(db.Boolean, nullable=False)
    can_take_calls = db.Column(db.Boolean, nullable=False)
    seats = db.Column(db.String, nullable=False)
    coffee_price = db.Column(db.Float, nullable=False)
    verified = db.Column(db.Boolean, nullable=False)
    user_comment = db.relationship('CommentReviews', backref='cafes', cascade="all, delete-orphan", lazy=True)

class CommentReviews(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    review = db.Column(db.String, nullable=False)
    cafe_id = db.Column(db.Integer, db.ForeignKey('cafes.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    parent_user = db.relationship('User', backref='comments')
    parent_cafe = db.relationship('Cafes', backref='comments')


class LoginForm(FlaskForm):
    email = EmailField('Email Address', [Length(min=6)])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    log_in = SubmitField('login')

class ForgotPasswordForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    reset_password = SubmitField('reset password')

class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password', [
        DataRequired(), Length(min=8, max=40),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    reset_password = SubmitField('reset password')

class CreateAccount(FlaskForm):
    username = StringField('Enter your username', validators=[DataRequired(), Length(min=5, max=40)])
    email = EmailField('Email Address', [Length(min=6)])
    password = PasswordField('Password', [
            DataRequired(), Length(min=8, max=40),
            validators.EqualTo('confirm', message='Passwords must match')
        ])
    confirm = PasswordField('Repeat Password')
    recaptcha = RecaptchaField()
    create_account = SubmitField()

class ReviewForm(FlaskForm):
    comment = CKEditorField('Review', render_kw={"class": "ckeditor-field"}, validators=[Length(min=5, max=80)])
    submit = SubmitField('Submit', render_kw={"class": "submit-button"})

class CompleteAccount(FlaskForm):
    username = StringField('Enter your username', validators=[DataRequired(), Length(min=5, max=40)])
    update_account = SubmitField('Update Account')

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    global google_check
    if google.authorized and google_check == 0:
        google_check += 1
        return redirect(url_for('google_login'))
    return render_template('home.html')

@app.route('/verify-account')
@login_required
def verify_account():
    if current_user.verified:
        return redirect(url_for('home'))
    token = generate_token(current_user.email)
    confirm_url = url_for("confirm_email", token=token, _external=True)
    html = render_template("verify.html", confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(current_user.email, subject, html)
    flash("A confirmation email has been sent via email.", "success")
    return redirect(url_for('home'))

@app.route('/request-inbox')
@admin_required
def inbox():
    unverified_places = db.session.execute(db.select(Cafes).filter_by(verified=False)).scalars()
    return render_template('inbox.html', unverified_places=unverified_places)

@app.route('/view-place/<int:place_id>', methods=['GET', 'POST'])
def view_place(place_id):
    place = db.session.execute(db.select(Cafes).filter_by(id=place_id)).scalar_one()
    gravatar = Gravatar(app, size=30, rating='g', default='retro', force_default=False, force_lower=False,
                        use_ssl=False, base_url=None)
    review_form = ReviewForm()
    comments = db.session.execute(db.select(CommentReviews).filter_by(cafe_id=place_id)).scalars()
    if place.verified == 0:
        if current_user.id == 1:
            return render_template('view-place.html', place=place, review_form=review_form, gravatar=gravatar, comments=comments)
        return redirect(url_for('home'))
    else:
        if review_form.validate_on_submit():
            if not current_user.is_authenticated:
                flash('You need to login to leave a review!', category='danger')
                return redirect(url_for('login'))
            if not current_user.verified:
                flash('You need to verify your account to leave a review!', category='danger')
                return redirect(url_for('view_place', place_id=place_id))
            db.session.add(CommentReviews(review=review_form.comment.data, cafe_id=place.id, user_id=current_user.id))
            db.session.commit()
            return redirect(url_for('view_place', place_id=place_id))
        return render_template('view-place.html', place=place, review_form=review_form, gravatar=gravatar, comments=comments)

@app.route('/delete-cafe/<int:id>')
def delete_cafe(id):
    place = db.session.execute(db.select(Cafes).filter_by(id=id)).scalar_one()
    db.session.delete(place)
    db.session.commit()
    return redirect(url_for('inbox'))

@app.route('/accept-cafe/<int:id>')
def accept_cafe(id):
    place = db.session.execute(db.select(Cafes).filter_by(id=id)).scalar_one()
    place.verified = True
    db.session.commit()
    return redirect(url_for('inbox'))

@app.route('/delete-comment/<int:id>')
def delete_comment(id):
    comment = db.session.execute(db.select(CommentReviews).filter_by(id=id)).scalar_one()
    cafe_id = comment.cafes.id
    db.session.delete(comment)
    db.session.commit()
    return redirect(url_for('view_place', place_id=cafe_id))

@app.route('/view-all')
def view_all_cafe():
    all_cafe = db.session.execute(db.select(Cafes).filter_by(verified=True)).scalars()
    return render_template('all-places.html', all_cafe=all_cafe)

@app.route('/add-new-location', methods=['GET', 'POST'])
def add_location():
    if request.method == 'POST':
        # Retrieve form data
        name = request.form.get('name')
        map_url = request.form.get('map_url')
        image_url = request.form.get('image_url')
        location = request.form.get('location')
        have_sockets = int(request.form.get('have_sockets'))
        have_toilet = int(request.form.get('have_toilet'))
        have_wifi = int(request.form.get('have_wifi'))
        can_take_calls = int(request.form.get('can_take_calls'))
        seats = request.form.get('seats')
        coffee_price = request.form.get('price')

        café = Cafes(name=name,
                     map_url=map_url,
                     img_url=image_url,
                     location=location,
                     has_sockets=have_sockets,
                     has_toilet=have_toilet,
                     has_wifi=have_wifi,
                     can_take_calls=can_take_calls,
                     seats=seats,
                     verified=False,
                     coffee_price=coffee_price)

        db.session.add(café)
        db.session.commit()

        flash('Your form will be process', category='success')
        return redirect(url_for('home'))
    return render_template('add-new-place.html')

@app.route('/login', methods=['GET', 'POST'])
@logout_required
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data
        try:
            user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one()
        except:
            flash("Email doesn't exist", category='danger')
            return render_template('login.html', login_form=login_form)
        if hash_password(password) == user.password:
            login_user(user)
            flash('successfully logged in', 'success')
            return redirect(url_for('home'))
        else:
            flash('Incorrect password', category="danger")
            return render_template('login.html', login_form=login_form)
    return render_template('login.html', login_form=login_form)

@app.route('/logout')
def logout():
    global google_check
    session.clear()
    google_check = 0
    flash('successfully logged out', 'success')
    return redirect(url_for('home'))

@app.route("/google-login", methods=['GET', 'POST'])
@logout_required
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    assert resp.ok, resp.text
    email = resp.json()["email"]
    user = User.query.filter_by(email=email).first()

    if not user:
        user = User(email=email, verified=True, password='Google')
        db.session.add(user)
        db.session.commit()
    if not user.verified:
        user.verified = True
        db.session.commit()

    login_user(user)
    if user.username == None:
        return redirect(url_for('create_username'))
    flash(f"logged in as {email}", 'success')
    return redirect(url_for("home"))

@app.route('/create-username', methods=['GET', 'POST'])
def create_username():
    username_form = CompleteAccount()
    if username_form.validate_on_submit():
        usernames = User.query.with_entities(User.username).all()
        usernames = [value[0] for value in usernames]
        username = username_form.username.data
        print(username)
        if username in usernames:
            flash('Username already taken', category='danger')
            return render_template('passwordRestore.html', forgot_form=username_form)
        current_user.username = username
        db.session.commit()
        print('your time to shine my man')
        flash(f"logged in as {current_user.email}", 'success')
        return redirect(url_for("home"))
    return render_template('passwordRestore.html', forgot_form=username_form)

@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
    if current_user.verified:
        flash("Account already confirmed.", category="success")
        return redirect(url_for("home"))
    email = confirm_token(token)
    user = User.query.filter_by(email=current_user.email).first_or_404()
    if user.email == email:
        user.verified = True
        db.session.add(user)
        db.session.commit()
        flash("You have confirmed your account. Thanks!", category="success")
    else:
        flash("The confirmation link is invalid or has expired.", category="danger")
    return redirect(url_for("home"))

@app.route('/change-password/<token>', methods=['GET', 'POST'])
@logout_required
def change_password(token):
    email = confirm_token(token)
    password_reset = PasswordResetForm()
    if password_reset.validate_on_submit():
        new_password = password_reset.password.data
        user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one()
        user.password = hash_password(new_password)
        db.session.commit()
        flash('Password has been changed successfully', category='success')
        return redirect(url_for('login'))
    return render_template('passwordRestore.html', forgot_form=password_reset)

@app.route('/forgot-password', methods=['GET', 'POST'])
@logout_required
def forgot_password():
    forgot_form = ForgotPasswordForm()
    if forgot_form.validate_on_submit():
        email = forgot_form.email.data
        all_email = User.query.with_entities(User.email).all()
        all_email = [value[0] for value in all_email]
        if email in all_email:
            token = generate_token(email)
            confirm_url = url_for("change_password", token=token, _external=True)
            html = render_template("reset_message.html", confirm_url=confirm_url)
            subject = "Reset Password"
            send_email(email, subject, html)
            flash('Reset password email sent', category='success')
            return redirect(url_for('login'))
        else:
            flash('email doesnt exist', category='danger')
            return render_template('passwordRestore.html', forgot_form=forgot_form)
    return render_template('passwordRestore.html', forgot_form=forgot_form)

@app.route('/Register-account', methods=['GET', 'POST'])
@logout_required
def register_account():
    register_form = CreateAccount()
    if register_form.validate_on_submit():
        username = register_form.username.data
        email = register_form.email.data
        password = hash_password(register_form.password.data)
        new_user = User(username=username, email=email, password=password)
        usernames = User.query.with_entities(User.username).all()
        usernames = [value[0] for value in usernames]
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exist login instead', category="danger")
            return redirect(url_for('login'))
        if username in usernames:
            flash('username has already been taken', category="danger")
            return redirect(url_for('register_account'))
        db.session.add(new_user)
        db.session.commit()
        token = generate_token(new_user.email)
        confirm_url = url_for("confirm_email" , token=token, _external=True)
        html = render_template("verify.html", confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(new_user.email, subject, html)
        login_user(new_user)
        flash("A confirmation email has been sent via email.", "success")
        return redirect(url_for('home'))
    return render_template('register.html', register_form=register_form)

if __name__ == '__main__':
    app.run(debug=True)