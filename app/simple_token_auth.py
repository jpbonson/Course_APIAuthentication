from functools import wraps
from flask import request, Response, jsonify


def _check_credentials(key, secret):
    return key == 'key' and secret == 'secret'


def generate_simple_token():
    auth = request.get_json()
    if 'key' not in auth or 'secret' not in auth:
        return Response('Must provide a key/secret pair\n', 400)
    if not _check_credentials(auth['key'], auth['secret']):
        return Response('Invalid key/secret pair\n', 404)
    token = {'access_token': 'abc123'}
    return jsonify(token)


def _check_auth(auth_type, token):
    return auth_type == 'Token' and token == 'abc123'


def _authenticate():
    """ Sends a 401 response with the type of auth expected """
    return Response(
        'Unauthorized, please login with the correct credentials\n', 401,
        {'WWW-Authenticate': 'Token'})


def requires_simple_token_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_type = None
        token = None
        try:
            auth = request.headers['authorization']
            auth_type, token = auth.split()
        except KeyError:
            return _authenticate()
        if not _check_auth(auth_type, token):
            return _authenticate()
        return f(*args, **kwargs)
    return decorated
