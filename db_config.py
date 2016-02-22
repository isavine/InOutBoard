import sys
import os
sys.path.append(os.path.abspath("../InOutBoard/instance"))
from init_setup import *
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import UserMixin
#from setup import app, db

app = Flask(__name__)
db = SQLAlchemy(app)
app.config.from_envvar('INOUTBOARD_SETTINGS', silent=False)

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.String, primary_key=True, unique=True)
    name = db.Column(db.String, unique=False)
    url = db.Column(db.String, nullable=False, unique=False)
    #email = db.Column(db.String, nullable=True, unique=True)

    in_out = db.Column(db.Boolean(), nullable=True, default=False)
    msg = db.Column(db.String, default='')

    first_name = db.Column(db.String(100), nullable=True, server_default='')
    last_name = db.Column(db.String(100), nullable=True, server_default='')
    extra = db.Column(db.String(100), nullable=True, server_default='')

    roles = db.relationship('Role', secondary='user_roles',
                backref=db.backref('user', lazy='dynamic'))

    def is_in(self):
        return self.in_out

class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=False)

# Define the UserRoles data model
class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id', ondelete='CASCADE'))

staff_role = Role(name='staff')
admin_role = Role(name='admin')

db.create_all()
init_admins(User, admin_role, db)

