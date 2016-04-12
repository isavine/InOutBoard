from db_config import User, Role, UserRoles, guest_role, dept_role, app, db
from flask import flash


def user_query(role):
    role = Role.query.filter_by(id=UserRoles.role_id).filter_by(name=role).one()
    users = role.users.filter_by(active=True).order_by(User.name)
    return users

def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"Error in the %s field - %s" % (
                getattr(form, field).label.text,
                error
            ), 'danger')

def get_role(role_name):
    roles = Role.query.all()
    for role in roles:
        if role.name == role_name:
            return role

