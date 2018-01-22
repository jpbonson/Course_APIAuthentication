from functools import wraps
from flask import request, Response


def _check_auth(username, password):
    return username == 'user' and password == 'pwd'


def _authenticate():
    """ Sends a 401 response with the type of auth expected """
    return Response(
        'Unauthorized, please login with the correct credentials\n', 401,
        {'WWW-Authenticate': 'Basic'}
    )


def requires_basic_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not _check_auth(auth.username, auth.password):
            return _authenticate()
        return f(*args, **kwargs)
    return decorated
