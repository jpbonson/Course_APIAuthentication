from flask import request, Response, jsonify
from app.basic_auth import requires_basic_auth

from flask import Flask
app = Flask(__name__)


@app.route('/basic_access', methods=['GET'])
@requires_basic_auth
def secret_page_basic():
    return "Accessed using Basic authentication!\n"


def _authenticate():
    """ Sends a 401 response with the type of auth expected """
    return Response(
        'Unauthorized, please login with the correct credentials\n', 401,
        {'WWW-Authenticate': 'Token'})


@app.route('/simple_token', methods=['POST'])
def get_simple_token():
    auth = request.get_json()
    if 'key' not in auth or 'secret' not in auth:
        return Response('Must provide a key/secret pair\n', 400)
    if auth['key'] != 'key' or auth['secret'] != 'secret':
        return Response('Invalid key/secret pair\n', 404)
    token = {'access_token': 'abc123'}
    return jsonify(token)


@app.route('/simple_token_access', methods=['GET'])
def secret_page_simple_token():
    auth_type = None
    token = None
    try:
        auth = request.headers['authorization']
        auth_type, token = auth.split()
    except KeyError:
        return _authenticate()
    if auth_type != "Token" or token != "abc123":
        return _authenticate()
    return "Accessed using simple token authentication!\n"


@app.route("/", methods=['GET'])
def hello():
    return "Welcome to the public route!\n"
