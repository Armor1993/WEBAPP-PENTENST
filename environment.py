from datetime import datetime

from flask import Flask
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect

user = 'root'
passwd = 'root'
host = 'localhost'
db_name = 'WEBAPPTEST'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Secrett!'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://{0}:{1}@{2}/{3}'.format(user, passwd, host, db_name)
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class Serializer(object):
    def serialize(self):
        ret = {}
        for c in inspect(self).attrs.keys():
            if isinstance(getattr(self, c), datetime):
                date = getattr(self, c)
                ret[c] = date.isoformat()
            else:
                ret[c] = getattr(self, c)
        return ret

    @staticmethod
    def serialize_list(l):
        return [m.serialize() for m in l]


class User(UserMixin, db.Model, Serializer):
    """
    User Table in the Database
    """
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    firstname = db.Column(db.String(15), nullable=False)
    lastname = db.Column(db.String(15), nullable=True)
    companyname = db.Column(db.String(20), nullable=False)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


class Scan(db.Model, Serializer):
    """
    Scan Table in Database
    """
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    scan_type = db.Column(db.String(5), nullable=True)
    date_created = db.Column(db.DateTime, nullable=False)
    date_started = db.Column(db.DateTime, nullable=True)
    date_completed = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.Integer, nullable=True)
    progress = db.Column(db.Integer, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('target.id'), nullable=False)
    output = db.Column(db.Text, nullable=True)


class Target(db.Model, Serializer):
    """
    Target Table in Database
    """
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    domain = db.Column(db.String(100), nullable=False)
    status = db.Column(db.Integer, nullable=True)
    key = db.Column(db.Text, nullable=True)
    time_created = db.Column(db.TIMESTAMP, nullable=True)


class Process(db.Model, Serializer):
    """
    Process Table in database
    """
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'))
    process = db.Column(db.String(10), nullable=False)
    status = db.Column(db.Integer, nullable=True, default=0)
    progress = db.Column(db.Integer, nullable=False, default=0)
    date_started = db.Column(db.DateTime, nullable=True)
    date_completed = db.Column(db.DateTime, nullable=True)
    output = db.Column(db.Text, nullable=True)
    command = db.Column(db.String(250), nullable=False)


class ZapOutput:
    def __init__(self, params=None):
        if not params:
            params = {}
        self.alert = params.get("alert", None)
        self.attack = params.get("attack", None)
        self.confidence = params.get("confidence", None)
        self.evidence = params.get("evidence", None)
        self.name = params.get("name", None)
        self.other = params.get("other", None)
        self.parameter = params.get("param", None)
        self.reference = params.get("reference", None)
        self.risk = params.get("risk", None)
        self.solution = params.get("risk", None)
