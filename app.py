from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Secrett!'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    firstname = db.Column(db.String(15), nullable=False)
    lastname = db.Column(db.String(15), nullable=True)
    companyname = db.Column(db.String(20), nullable=False)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


class Scan(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime, nullable=False)
    date_started = db.Column(db.DateTime, nullable=True)
    date_completed = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.Integer, nullable=False)
    progress = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('target.id'), nullable=False)


class Target(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    domain = db.Column(db.String(100), nullable=False)
    status = db.Column(db.Integer, nullable=True)
    key = db.Column(db.Text, nullable=False)


class Process(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'))
    process = db.Column(db.String(10), nullable=False)
    status = db.Column(db.Integer, nullable=False)
    progress = db.Column(db.Integer, nullable=False)
    date_started = db.Column(db.DateTime, nullable=True)
    date_completed = db.Column(db.DateTime, nullable=True)
    output = db.Column(db.Text, nullable=False)
    command = db.Column(db.String(250), nullable=False)


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
    if current_user.is_authenticated():
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

        # TODO FLASH INVALID USERNAME PASSWORD
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

        # TODO FLASH CREATED!
        return '<h1>New user has been created!</h1>'

    return render_template('login.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/scan/list')
@login_required
def scans():
    return render_template('scan/list.html', name=current_user.username, scans=Scan.query.filter_by(current_user.id).all())


@app.route('/scan/<int:scan_id>', methods=['GET', 'POST'])
@app.route('/scan')
@login_required
def scan_form(scan_id=False):
    query = Scan.query.filter_by(scan_id=scan_id)
    if request.method == 'POST':
        if query:
            # update db
            updict = request.json
            query.title = updict['title']
            query.date_created = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            query.user_id = current_user.id
            query.target_id = updict['target_id']
            db.session.commit()
        else:
            # TODO
            # create
            newscan = Scan()
            newdict = request.json
            newscan.title = newdict['title']
            newscan.date_created = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            newscan.target_id = newdict['target_id']
            db.session.add(newscan)
            db.session.commit()
            scan_id = newscan.id
            # call the function to create and bind the scan processes id to the scan processes
            # get new scan object created after scan creation
            # return the page with the new creation data

    newquery = Scan.query.filter_by(scan_id=scan_id)
    return render_template('scan/form.html', name=current_user.username, scan=newquery)


@app.route('/scan/<int:scan_id>/report')
@login_required
def scan_report(scan_id=False):
    if scan_id is False:
        return redirect(url_for('scan/list'))
    else:
        scan_obj = Scan.query.filterby(scan_id=scan_id)
        if scan_obj:
            return render_template('scan/form.html', name=current_user.username, scan=scan_obj)
        else:
            # Scan not Found
            # flash that scan wasnt found on page
            # redirect to scan list
            return redirect(url_for('scan/list'))


@app.route('/target/list')
@login_required
def target():
    return render_template('target/list.html', name=current_user.username, scan=Scan.query.filter_by(user_id=current_user.id).all())


@app.route('/target/<int:target_id>')
@app.route('/target')
@login_required
def target_form(target_id=False):
    query = Target.query.filter_by(target_id=target_id)
    if request.method == 'POST':
        if target_id is False:
            # TODO
            # create
            new_target = Target()
            newdict = request.json
            new_target.domain = newdict['domain']
            new_target.user_id = current_user.id
            db.session.add(new_target)
            db.session.commit()
            target_id = new_target.id
            # create the new target by adding to db
            # get net targt obj
        else:
            # update
            updict = request.json
            query.title = updict['title']
            query.user_id = current_user.id
            query.domain = updict['domain']
            db.session.commit()
    else:
        if query:
            # view
            return render_template('target/form.html', name=current_user.username, target=query)
        else:
            # TODO
            # create
            # create the new target by adding to db
            # get new target obj
            new_target = Target()
            newdict = request.json
            new_target.domain = newdict['domain']
            new_target.user_id = current_user.id
            db.session.add(new_target)
            db.session.commit()
            target_id = new_target.id

    return render_template('target/form.html', name=current_user.username, target=target_id)


@app.route('/target/<int:target_id>/authorize')
@login_required
def target_authorize(target_id=False):
    query = Target.query.filter_by(target_id=target_id)
    if target_id is False:
        redirect(url_for('target/list'))
    if request.method == 'POST':
        # authorize
        pass
    else:
        return render_template('target/authorize.html', name=current_user.username, target=query)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
