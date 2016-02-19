from setup import app, db
from db_config import User, Role, UserRoles, staff_role, admin_role

def init_admins():
	if (User.query.get('1069133') == None):
	    new_user = User(id='1069133',name="Tommy Le Huynh",first_name="Tommy",
	        last_name="Huynh",url="http://tommyhuynh.me/", in_out=True)
	    new_user.roles.append(admin_role)
	    db.session.add(new_user)
	    db.session.commit()
	if (User.query.get('335588') == None):
	    new_user = User(id='335588',name="Igor Savine",first_name="Igor",
	        last_name="Savine",
			url="https://math.berkeley.edu/people/staff/igor-savine",
			in_out=True)
	    new_user.roles.append(admin_role)
	    db.session.add(new_user)
	    db.session.commit()

db.create_all()
init_admins()
