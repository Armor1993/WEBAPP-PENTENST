from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Secrett!'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(15))
    lastname = db.Column(db.String(15))
    companyname = db.Column(db.String(20))
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=16)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    firstname = StringField('first name', validators=[InputRequired(), Length(min=4, max=50)])
    lastname = StringField('last name', validators=[InputRequired(), Length(min=4, max=50)])
    companyname = StringField('company name', validators=[InputRequired(), Length(min=4, max=50)])
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    if (user.is_authenticated()):
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/scan/list')
@login_required
def scans():
    return render_template('scan/list.html', name=current_user.username)


@app.route('/scan/<int:scan_id>')
@app.route('/scan')
@login_required
def scan_form(scan_id=False):
    # if request method is post
        # pobably create or update
            # if scan_id exists:
                # update
            # else:
                # create
    # else:
        # if scan if exists:
            # view
        # else:
            # create
    return render_template('scan/form.html', name=current_user.username)


@app.route('/scan/<int:scan_id>/report')
@login_required
def scan_report(scan_id=False):
    # if scan_id false:
        # redirect to scan/list
    # get scan process outputs
    pass


@app.route('/target/list')
@login_required
def targets():
    return render_template('target/list.html', name=current_user.username)


@app.route('/target/<int:target_id>')
@app.route('/target')
@login_required
def target_form(target_id=False):
    # if request method is post
    # pobably create or update
    # if target_id exists:
    # update
    # else:
    # create
    # else:
    # if target if exists:
    # view
    # else:
    # create
    return render_template('target/form.html', name=current_user.username)



@app.route('/target/<int:target_id>/authorize')
@login_required
def target_authorize(target_id=False):
    # if target_id false:
    # redirect to target/list
    # get the target from database to show location of auth key
    # if request method is post
    # authorize request
    # else:
    return render_template('target/authorize.html', name=current_user.username)


@app.route('/webManagement')
@login_required
def webManagement():
    return render_template('webManagement.html', name=current_user.username)


@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html', name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)