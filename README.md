# Import initial settings:
  $ export INOUTBOARD_SETTINGS=instance/settings.py
  $ python app.py

# Example of settings.py:
    SECRET_KEY = '\xdd\xa6k\xe4\xff\x1c\x8eJ=nh\x1b{5\xd1\xe3\x9e\xa5\xfe\xe2\x9f\xeb\x07\x81'
    SESSION_COOKIE_NAME = 'in_out_board'
    CAS_URL = 'https://auth.example.com/cas/'
    SERVICE_URL = 'https://www.example.com/inout/validate'
    LDAP_SERVER = 'ldaps://ldap.example.com'
    LDAP_BASE = 'ou=people,dc=example,dc=com'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///inoutboard.db'
    PERMANENT_SESSION_LIFETIME = 3600
    APPLICATION_ROOT = '/inout'
    SERVER_PORT = 5000
    ADMIN_USERS = [
      dict(id='12345678', name='John Doe', first_name='John', last_name='Doe',
        url='http://johndoe.me/')
    ]
