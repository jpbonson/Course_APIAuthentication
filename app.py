from functools import wraps
from flask import request, Response

from flask import Flask
app = Flask(__name__)


def check_auth(username, password):
    return username == 'user' and password == 'pwd'


def authenticate():
    """ Sends a 401 response with the type of auth expected """
    return Response(
        'Unauthorized, please login with the correct credentials\n', 401,
        {'WWW-Authenticate': 'Basic'}
    )


def requires_basic_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route('/basic')
@requires_basic_auth
def secret_page():
    return "Accessed using Basic authentication!\n"


@app.route("/")
def hello():
    return "Hello World!\n"
