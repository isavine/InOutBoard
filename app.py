import json
# from setup import app, db
from db_config import User, Role, UserRoles, staff_role, admin_role, app, db
from flask import Flask, request, jsonify, session, g, redirect, url_for, abort, \
     render_template, flash, json
from ldap import initialize, SCOPE_SUBTREE
from urllib import urlencode, urlopen
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, login_user, UserMixin, login_required, logout_user, \
      fresh_login_required
from datetime import timedelta




# app = Flask(__name__)
# db = SQLAlchemy(app)

# app.config.update(dict(
#     DEBUG=True,
#     SECRET_KEY='supersecretdevelopmentkey',
#     SESSION_COOKIE_NAME = 'in_out_board',
#     CAS_URL = 'https://auth.berkeley.edu/cas/',
#     SERVICE_URL = 'http://localhost:5000/validate',
#     LDAP_SERVER = 'ldap://nds-test.berkeley.edu',
#     LDAP_BASE = 'ou=people,dc=berkeley,dc=edu',
#     SQLALCHEMY_DATABASE_URI = 'sqlite:////home/tommy/work/InOutBoard/.inoutboard.db',
#     SQLALCHEMY_TRACK_MODIFICATIONS = True
# ))
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


app.config.from_envvar('INOUTBOARD_SETTINGS', silent=False)

@app.before_request
def func():
    session.modified = True


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=120)


# class User(db.Model):
#     __tablename__ = 'user'

#     uid = db.Column(db.String, primary_key=True, unique=True)
#     name = db.Column(db.String, unique=False)
#     url = db.Column(db.String, nullable=False, unique=False)
#     #email = db.Column(db.String, nullable=True, unique=True)

#     in_out = db.Column(db.Boolean(), nullable=True, default=False)
#     msg = db.Column(db.String, default='')

#     first_name = db.Column(db.String(100), nullable=True, server_default='')
#     last_name = db.Column(db.String(100), nullable=True, server_default='')

#     roles = db.relationship('Role', secondary='user_roles',
#                 backref=db.backref('user', lazy='dynamic'))

#     def is_in(self):
#         return self.in_out

# # class UserSchema(Schema):
# #     id = fields.Str(dump_only=True)
# #     name = fields.Str()
# #     #email = fields.Str()
# #     url = fields.Str()
# #     in_out = fields.Boolean()
# #     msg = fields.Str()
# #     first_name = fields.Str()
# #     last_name = fields.Str()

# class Role(db.Model):
#     __tablename__ = 'role'
#     id = db.Column(db.Integer(), primary_key=True)
#     name = db.Column(db.String(50), unique=False)

# # Define the UserRoles data model
# class UserRoles(db.Model):
#     __tablename__ = 'user_roles'
#     id = db.Column(db.Integer(), primary_key=True)
#     user_id = db.Column(db.Integer(), db.ForeignKey('user.uid', ondelete='CASCADE'))
#     role_id = db.Column(db.Integer(), db.ForeignKey('role.id', ondelete='CASCADE'))


# # db_adapter = SQLAlchemyAdapter(db, User)
# # user_manager = UserManager(db_adapter, app)
# staff_role = Role(name='staff')
# admin_role = Role(name='admin')
# # user_schema = UserSchema()
# # users_schema = UserSchema(many=True)
@login_manager.unauthorized_handler
def unauthorized_callback():
    flash('Cannot validate authentication request.', 'danger')
    return render_template("base.html")


@app.route('/logout')
@login_required
def logout():
    session['logged_in'] = False
    session['admin'] = False
    session['staff'] = False
    flash('You were logged out', 'success')
    logout_user()
    # url = 'https://auth.berkeley.edu/cas/logout'
    # return redirect(url,307)
    return render_template("base.html")


@app.route('/', methods=['GET', 'POST'])
def login():
    session['admin'] = False
    session['staff'] = False
    url = app.config['CAS_URL'] + 'login?' + \
        urlencode({'service': app.config['SERVICE_URL']})
    return redirect(url, 307)


@app.route('/validate')
def validate():
    if request.args.has_key('ticket'):
        url = app.config['CAS_URL'] + 'validate?' + \
            urlencode({'service': app.config['SERVICE_URL'],
            'ticket': request.args['ticket']})
        page = urlopen(url)
        lines = page.readlines()
        page.close()
        #print lines

        ldap_obj = initialize(app.config['LDAP_SERVER'])
        if lines[0].strip() == 'yes':
            
            uid = lines[1].strip()
            session['UID'] = uid
            ldap_obj.simple_bind_s()
            result = ldap_obj.search_s(app.config['LDAP_BASE'], SCOPE_SUBTREE,
                '(uid=%s)' % uid)
            #print result
            name = result[0][1]['displayName'][0].title()
            session['name'] = name
            #session['logout'] = False
            #print session
            user = User.query.get(session['UID'])
            if not (user):
                session['admin'] = False
                session['staff'] = False
                session['logged_in'] = False
                flash('You are not allowed access to this page.', 'danger')
                return render_template("base.html")
            flash('You were logged in as %s' % name, 'success')
            login_user(user)
            session['logged_in'] = True
            #return redirect(url_for("render_role_select")) #production
            # uncomment below when going commercial
            
            return redirect(url_for("determine_user_type"))
        return render_template("board.html", users=db.session.query(User))
    flash('Cannot validate authentication request', 'danger')
    return redirect(url_for('login'))

@app.route('/dut')
@login_required
def determine_user_type():
    # Change if want multiple roles per user.
    if not (session['logged_in']):
        session["admin"] = False
        session["staff"] = False
        session["role_switch"] = False
        return redirect(url_for('login'))
    user_type = User.query.get(session['UID']).roles[0].name
    if (user_type == 'admin'):
        session["admin"] = True
        session["staff"] = False
        session["role_switch"] = True
    elif (user_type == 'staff'):
        session["admin"] = False
        session["staff"] = True
        session["role_switch"] = False
    return redirect(url_for('render_board'))



@app.route('/board')
@login_required
def render_board():
    users = db.session.query(User)
    uids = [user.id for user in users]
    return render_template("board.html", users=users, uids = uids,
        admin = session["admin"], staff= session["staff"], role_switch= session["role_switch"],
        logged_in = session['logged_in'])


# user as an admin role switcher
@app.route('/role_select') #production
def render_role_select():
    return render_template("role_select.html")

@app.route('/role_select', methods=['POST']) #production
def role_select():
    selected = request.form["selected"]
    if (selected == 'Admin'):
        session["admin"] = True
        session["staff"] = False
    elif (selected == 'Staff'):
        session["admin"] = False
        session["staff"] = True
    return redirect(url_for('render_board'))

@app.route('/inOutToggle/<uid>')
@login_required
def inOutToggle(uid):
	print("going in here")
	user = User.query.get(uid)
	if user.in_out:
		user.in_out = False
		db.session.commit()
	else:
		user.in_out = True
		db.session.commit()
	return redirect(url_for('render_board'))

@app.route('/message_submit')
@login_required
def message_submit():
    new_msgs = request.args.get('new_msgs')
    parsed_msgs = json.loads(new_msgs)

    for msg in parsed_msgs:
        user = User.query.get(msg['uid'])
        new_msg = msg['msg']
        if user.msg != new_msg:
            user.msg = new_msg
            db.session.commit()
    return jsonify()

@app.route('/check_change')
@login_required
def check_change():
    srvr_users = db.session.query(User).all()
    result = users_schema.dump(srvr_users)
    return jsonify({'users': result.data })

@app.route('/edit_user_page/<uid>')
@login_required
def edit_user_page(uid):
    user = User.query.get(uid)
    role = user.roles[0].name
    staff = False
    if (role == "staff"):
        staff = True
    return render_template("edit_add_user.html", curr_uid=session['UID'],
        edit_mode=True, add_mode=False, user=user, staff=staff)

@app.route('/edit_user/<uid>', methods=["POST"])
@login_required
def edit_user(uid):
    user = User.query.get(uid)
    user.id = request.form['uid']
    user.first_name = request.form['first-name']
    user.last_name = request.form['last-name']
    user.url = request.form['url']
    user.name = user.first_name + " " + user.last_name
    selected_role = request.form["selected_role"]
    if not (user.roles[0].name == selected_role):
        if selected_role == 'staff':
            user.roles.pop(0)
            user.roles.append(staff_role)
        else:
            user.roles.pop(0)
            user.roles.append(admin_role)
    db.session.commit()
    return redirect(url_for('render_board'))


@app.route('/add_user_page')
@fresh_login_required
def add_user_page():
    return render_template("edit_add_user.html", edit_mode=False, add_mode=True)

@login_manager.needs_refresh_handler
def refresh():
    flash('NEED A FRESH LOGIN', 'danger')
    return render_template("base.html")


@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    fn = request.form['first-name']
    ln = request.form['last-name']
    new_user = User(id=request.form['uid'],name=fn + " " + ln,first_name=fn,
        last_name=ln,url=request.form['url'], in_out=False)
    if (request.form["selected_role"] == "staff"):
        print("added new member to staff")
        new_user.roles.append(staff_role)
    else:
        print("added new member to admin")
        new_user.roles.append(admin_role)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('render_board'))


if __name__ == '__main__':
    from werkzeug.serving import run_simple
    from werkzeug.wsgi import DispatcherMiddleware
    application = DispatcherMiddleware(Flask('inoutboard'), {
        app.config['APPLICATION_ROOT']: app,
    })
    db.create_all()
    #app.run()
    # run_simple('localhost', 5004, application, use_reloader=True)
    run_simple('localhost', 5000, application, use_reloader=True)

# If no database:
    # export INOUTBOARD_SETTINGS=instance/test_settings.py
    # python db_config.py
    # python app.py

# If existing database:
    # export INOUTBOARD_SETTINGS=prod_settings.py
    # python setup.py
    # python app.py
