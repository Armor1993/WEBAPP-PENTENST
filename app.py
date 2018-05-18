# import datetime
import sys
from environment import *
from nmap import Nmap
from zaproxy import Zap
from os import path, walk
from flask import render_template, redirect, url_for, request
from flask_login import login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length


@login_manager.user_loader
def load_user(user_id) -> User:
    """
    Loads user from database based on given user_id
    :param user_id:
    :return: User
    """
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
    if current_user.is_authenticated:
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
        else:
            # TODO FLASH INVALID USERNAME PASSWORD
            return '<h1>Invalid username or password</h1>'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')

        new_user = User()
        new_user.username = form.username.data
        new_user.email = form.email.data
        new_user.password = hashed_password
        new_user.firstname = form.firstname.data
        new_user.lastname = form.lastname.data
        new_user.companyname = form.companyname.data

        db.session.add(new_user)
        db.session.commit()

        # TODO FLASH CREATED!
        return '<h1>New user has been created!</h1>'

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/scans')
@login_required
def scans():
    scan = Scan.query.filter_by(user_id=current_user.id).all()
    return render_template('scan/list.html', name=current_user.username, scans=scan)


@app.route('/scan/<int:scan_id>', methods=['GET', 'POST'])
@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan_form(scan_id=False):
    query = Scan.query.filter_by(id=scan_id).first()
    targets = Target.query.filter_by(user_id=current_user.id).all()
    if request.method == 'POST':
        print(request.form)
        if query:
            query.title = request.form['target']
            query.date_created = datetime.now()
            query.user_id = current_user.id
            query.target_id = request.form['target_id']
            db.session.commit()
        else:
            newscan = Scan()
            try:
                newscan.target_id = request.form['target']
                target_query = Target.query.filter_by(id=request.form['target']).first()
                newscan.title = target_query.domain
                newscan.user_id = current_user.id
                newscan.date_created = datetime.now()
                newscan.scan_type = ""
                newscan.progress = 0
                newscan.status = 0
                if request.form.get("all", False) or (
                        request.form.get("nmap", False) and request.form.get("zap", False) and request.form.get("w3af",
                                                                                                                False)):
                    newscan.scan_type = "all"
                    Nmap.create_nmprocess(newscan.id)
                    Zap.create_process(newscan.id)
                else:
                    if request.form.get("nmap", False):
                        newscan.scan_type += "n"
                        Nmap.create_nmprocess(newscan.id)
                    if request.form.get("zap", False):
                        newscan.scan_type += "z"
                        Zap.create_process(newscan.id)
                    if request.form.get("w3af", False):
                        newscan.scan_type += "w"
                if len(newscan.scan_type) == 0:
                    newscan.scan_type = None
            except Exception as ex:
                print(str(ex))
            db.session.add(newscan)
            db.session.commit()
            scan_id = newscan.id
            # call the function to create and bind the scan processes id to the scan processes
            # get new scan object created after scan creation
            # return the page with the new creation data
    newquery = Scan.query.filter_by(id=scan_id).first()
    return render_template('scan/form.html', name=current_user.username, scan=newquery, targets=targets)


@app.route('/scan/<int:scan_id>/report')
@login_required
def scan_report(scan_id=False):
    if scan_id is False:
        return redirect(url_for('scan/list'))
    else:
        scan_obj = Scan.query.filterby(id=scan_id).first()
        if scan_obj:
            return render_template('scan/form.html', name=current_user.username, scan=scan_obj)
        else:
            # Scan not Found
            # flash that scan wasnt found on page
            # redirect to scan list
            return render_template('scan/scans.html', name=current_user.username)


@app.route('/target/list')
@login_required
def target():
    targets = Target.query.filter_by(user_id=current_user.id).all()
    return render_template('target/list.html', name=current_user.username, targets=targets)


@app.route('/target/<int:target_id>', methods=['GET', 'POST'])
@app.route('/target', methods=['GET', 'POST'])
@login_required
def target_form(target_id=False):
    query = Target.query.filter_by(id=target_id).first()
    if request.method == 'POST':
        print(request.form)
        try:
            if target_id is False:
                new_target = Target()
                new_target.domain = request.form['domain']
                if request.form.get("all", False):
                    # add a scan object that performs all scans
                    print("SCANTYPE: all")
                    new_target.scan_type = "all"
                else:
                    if request.form.get("nmap", False):
                        print("SCANTYPE: nmap")
                        new_target.scan_type = "nmap"
                        Nmap.create_nmprocess(new_target.id)
                        # Add nmap scan
                        pass
                    if request.form.get("zap", False):
                        print("SCANTYPE: zap")
                        new_target.scan_type = "zap"
                        # add zap scan
                        pass
                    if request.form.get("w3af", False):
                        print("SCANTYPE: w3af")
                        new_target.scan_type = "w3af"
                        # add w3af scan
                        pass
                if request.form["date"]:
                    if request.form["time"]:
                        # append them and create a timestamp to add to db
                        pass
                    else:
                        # append them and create a timestamp to add to db
                        pass
                else:
                    new_target.scan_time = datetime.now()
                    pass
                new_target.time_created = datetime.now()
                new_target.user_id = current_user.id
                db.session.add(new_target)
                db.session.commit()
                sys.stderr.write("ADDED: " + str(new_target.__dict__))
                # get new targt obj
                # create query based on new target
            else:
                # update
                query.user_id = current_user.id
                query.domain = request.form['domain']
                # get target from database with id
                db.session.commit()
        except Exception as ex:
            print(str(ex))
    elif request.method == "GET" and query:
        pass
    else:
        # create not found message and redirect to list
        pass
    return render_template('target/form.html', name=current_user.username, target=query)


@app.route('/target/delete/<target_id>', methods=['GET'])
@login_required
def target_delete(target_id=False):
    Target.query.filter_by(id=target_id).delete()
    db.session.commit()
    targets = Target.query.filter_by(user_id=current_user.id).all()
    return render_template('target/list.html', name=current_user.username, targets=targets)


@app.route('/scan/delete/<scan_id>', methods=['GET'])
@login_required
def scan_delete(scan_id=False):
    Scan.query.filter_by(id=scan_id).delete()
    db.session.commit()
    scan = Scan.query.filter_by(user_id=current_user.id).all()
    return render_template('scan/list.html', name=current_user.username, scans=scan)


@app.route('/target/<int:target_id>/authorize')
@login_required
def target_authorize(target_id=False):
    query = Target.query.filter_by(id=target_id).first()
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


@app.route('/testreport')
@login_required
def test_report():
    return render_template('reports.html', name=current_user)


if __name__ == '__main__':
    extra_dirs = ['/root/PycharmProjects/WEBAPP-PENTENST/templates']
    extra_files = extra_dirs[:]
    db.create_all()
    for extra_dir in extra_dirs:
        for dirname, dirs, files in walk(extra_dir):
            for filename in files:
                filename = path.join(dirname, filename)
                if path.isfile(filename):
                    extra_files.append(filename)

    app.run(extra_files=extra_files, debug=True)
