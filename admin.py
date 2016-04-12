from flask import Blueprint
from db_config import User, Role, UserRoles, guest_role, dept_role, app, db
from flask import Flask, request, jsonify, session, g, redirect, url_for, abort, \
     render_template, flash, json
from helpers import user_query, flash_errors, get_role
from datetime import date
from flask.ext.login import LoginManager, login_user, UserMixin, login_required, logout_user, \
      fresh_login_required
from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Email, URL
from functools import wraps

admin = Blueprint("admin", __name__, template_folder = "templates/admin")

class UserForm(Form):
    first_name = StringField('First', validators=[DataRequired()])
    last_name = StringField('Last', validators=[DataRequired()])
    UID = IntegerField("UID", validators=[DataRequired()])
    URL = StringField("URL", validators=[DataRequired(), URL()])
    
# http://flask.pocoo.org/snippets/98/
def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not has_user_role(roles):
                return unauthorized_entry()
            return f(*args, **kwargs)
        return wrapped
    return wrapper

def has_user_role(roles):
    user = User.query.get(session['UID'])
    for role in user.roles:
        if role.name in roles:
            return True
    return False

def unauthorized_entry():
    flash('You are not allowed to see this page', 'warning')
    return render_template('base.html', title=app.config['BASE_HTML_TITLE'])

@admin.route("/")
@requires_roles("admin")
def index():

	session['dept'] = True
	session['staff'] = True
	session['admin'] = True
	return redirect(url_for("admin.render_board"))


@admin.route("/admin_board")
@requires_roles("admin")
def render_board():
	users = user_query("staff")
	return render_template('admin/admin_board.html', title=app.config['BASE_HTML_TITLE'], 
		date=date.today().strftime('%a %m/%d/%Y'), users=users, admin = session['admin'], 
		staff= session['staff'],role_switch = True, dept=session['dept'] )

@admin.route('/role_select')
@login_required
def render_role_select():
    return render_template('admin/role_select.html', title=app.config['BASE_HTML_TITLE'])


@admin.route('/role_select', methods=['POST'])
@login_required
def role_select():
    selected = request.form['selected']
    session['dept'] = True
    session['staff'] = False
    if (selected == 'Admin'):
        session['admin'] = True
    elif (selected == 'Staff'):
        session['admin'] = False
        session['staff'] = True
    elif (selected == 'Department'):
        session['admin'] = False
    else:
        session['dept'] = False
        session['admin'] = False
    return redirect(url_for('admin.render_board'))

@admin.route('/add_user', methods=['POST', 'GET'])
@login_required
def add_user():
    form = UserForm()

    if form.validate_on_submit():
        fn = request.form['first_name']
        ln = request.form['last_name']
        new_user = User(id=request.form['UID'],name=fn + ' ' + ln,first_name=fn,
            last_name=ln,url=request.form['URL'], in_out=False, active=True)

        for role in Role.query.all():
            if request.form.get(role.name):
                new_user.roles.append(get_role(role.name))

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('admin.render_board'))

    flash_errors(form)
    return render_template('admin/edit_add_user.html', title=app.config['BASE_HTML_TITLE'],
        edit_mode=False, add_mode=True, roles=Role.query.all(), form=form)


@admin.route('/edit_user/<uid>', methods=['POST', 'GET'])
@login_required
def edit_user(uid):
    user = User.query.get(uid)
    form = UserForm(first_name=user.first_name, last_name=user.last_name, URL=user.url, UID=user.id)
    roles = user.roles

    if form.validate_on_submit():
        user.id = request.form['UID']
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.url = request.form['URL']
        user.name = user.first_name + ' ' + user.last_name
        
        for role in Role.query.all():
            # Role is checked
            if request.form.get(role.name):
                if role not in user.roles:
                    user.roles.append(get_role(role.name))
            # Role is unchecked
            else:
                if role in user.roles:
                    user.roles.remove(role)
        db.session.commit()
        return redirect(url_for('admin.render_board'))

    flash_errors(form)
    return render_template('admin/edit_add_user.html', title=app.config['BASE_HTML_TITLE'],
        edit_mode=True, add_mode=False, user=user, user_roles = roles, roles=Role.query.all(), form=form)