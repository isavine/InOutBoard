import json
from db_config import User, Role, UserRoles, guest_role, dept_role, app, db
from flask import Flask, request, jsonify, session, g, redirect, url_for, abort, \
     render_template, flash, json
from ldap import initialize, SCOPE_SUBTREE
from urllib import urlencode, urlopen
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, login_user, UserMixin, login_required, logout_user, \
      fresh_login_required
from datetime import date

login_manager = LoginManager()
login_manager.init_app(app)
app.config.from_envvar('INOUTBOARD_SETTINGS', silent=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.before_request
def func():
    session.modified = True


@app.before_request
def make_session_permanent():
    session.permanent = True
    return


@login_manager.unauthorized_handler
def unauthorized_callback():
    flash('You are logged out. Please login.', 'warning')
    return render_template('base.html', title=app.config['BASE_HTML_TITLE'])


@app.route('/logout')
# @login_required
def logout():
    # flash('You were logged out.', 'success')
    logout_user()
    session['logged_in'] = False
    session['admin'] = False
    session['staff'] = False
    return render_template('base.html', title=app.config['BASE_HTML_TITLE'])


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
        if lines[0].strip() == 'yes':
            uid = lines[1].strip()
    elif request.args.has_key('uid') and session['admin']:
        uid = request.args['uid']
    else:
        uid = None
    if uid:
        ldap_obj = initialize(app.config['LDAP_SERVER'])
        ldap_obj.simple_bind_s()
        result = ldap_obj.search_s(app.config['LDAP_BASE'], SCOPE_SUBTREE, '(uid=%s)' % uid)
        if result:
            print(result)
            session['UID'] = uid
            name = result[0][1]['displayName'][0].title()
            session['name'] = name
            print(session['UID'])
            user = User.query.get(session['UID'])
            if user:
                flash('You were logged in as %s' % name, 'success')
                login_user(user)
                session['logged_in'] = True
                return redirect(url_for('who'))
    flash('You do not have permission to access this page.', 'danger')
    return redirect(url_for('logout'))


def user_query(role):
    role = Role.query.filter_by(id=UserRoles.role_id).filter_by(name=role).one()
    users = role.users.filter_by(active=True).order_by(User.name)
    return users


@app.route('/who')
@login_required
def who():
    user_type = User.query.get(session['UID']).roles[0].name
    session['dept'] = True
    session['role_switch'] = False
    session['admin'] = False
    session['staff'] = False
    if (user_type == 'admin'):
        session['admin'] = True
        session['role_switch'] = True
    elif (user_type == 'staff'):
        session['staff'] = True
    elif (user_type == 'guest'):
        session['dept'] = False
    return redirect(url_for('render_board'))


@app.route('/board')
@login_required
def render_board():
    users = user_query("staff")
    return render_template('board.html', title=app.config['BASE_HTML_TITLE'],
        date=date.today().strftime('%a %m/%d/%Y'), users=users,
        admin = session['admin'], staff= session['staff'],
        role_switch= session['role_switch'], dept=session['dept'])


@app.route('/role_select')
@login_required
def render_role_select():
    return render_template('role_select.html', title=app.config['BASE_HTML_TITLE'])


@app.route('/role_select', methods=['POST'])
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
    return redirect(url_for('render_board'))


@app.route('/inOutToggle')
@login_required
def inOutToggle():
    uid = request.args.get('uid')
    user = User.query.get(uid)
    if user.in_out:
        user.in_out = False
        db.session.commit()
    else:
        user.in_out = True
        db.session.commit()
    return jsonify(state = user.in_out)


@app.route('/message_submit')
@login_required
def message_submit():
    new_msgs = request.args.get('new_msgs')
    parsed_msgs = json.loads(new_msgs)

    for msg in parsed_msgs:
        user = User.query.get(msg['uid'])
        new_msg = msg['msg']
        if new_msg.isspace():
            new_msg = ""
        if user.msg != new_msg:
            user.msg = new_msg.strip()
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
    roles = user.roles
    print(roles)
    return render_template('edit_add_user.html', title=app.config['BASE_HTML_TITLE'],
        curr_uid=session['UID'],
        edit_mode=True, add_mode=False, user=user, user_roles = roles, roles=Role.query.all())


@app.route('/edit_user/<uid>', methods=['POST'])
@login_required
def edit_user(uid):
    user = User.query.get(uid)
    user.id = request.form['uid']
    user.first_name = request.form['first-name']
    user.last_name = request.form['last-name']
    user.url = request.form['url']
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
    return redirect(url_for('render_board'))


@app.route('/add_user_page')
@login_required
def add_user_page():
    return render_template('edit_add_user.html', title=app.config['BASE_HTML_TITLE'],
        edit_mode=False, add_mode=True, roles=Role.query.all())


@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    fn = request.form['first-name']
    ln = request.form['last-name']
    new_user = User(id=request.form['uid'],name=fn + ' ' + ln,first_name=fn,
        last_name=ln,url=request.form['url'], in_out=False, active=True)

    for role in Role.query.all():
        if request.form.get(role.name):
            new_user.roles.append(get_role(role.name))

    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('render_board'))

def get_role(role_name):
    roles = Role.query.all()
    for role in roles:
        if role.name == role_name:
            return role

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    from werkzeug.wsgi import DispatcherMiddleware
    application = DispatcherMiddleware(Flask('inoutboard'), {
        app.config['APPLICATION_ROOT']: app,
    })
    db.create_all()
    run_simple('localhost', app.config['SERVER_PORT'], application, use_reloader=True)
