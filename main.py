from app.basic_auth import requires_basic_auth
from app.simple_token_auth import generate_simple_token, requires_simple_token_auth
from app.jwt_token_auth import generate_jwt_token, requires_jwt_token_auth

from flask import Flask
app = Flask(__name__)


@app.route('/basic_access', methods=['GET'])
@requires_basic_auth
def secret_page_basic():
    return "Accessed using Basic authentication!\n"


@app.route('/simple_token', methods=['POST'])
def get_simple_token():
    return generate_simple_token()


@app.route('/simple_token_access', methods=['GET'])
@requires_simple_token_auth
def secret_page_simple_token():
    return "Accessed using simple token authentication!\n"


@app.route('/token', methods=['POST'])
def get_jwt_token():
    return generate_jwt_token()


@app.route('/token_access', methods=['GET'])
@requires_jwt_token_auth
def secret_page_jwt_token():
    return "Accessed using OAuth + JWT token authentication!\n"


@app.route("/", methods=['GET'])
def hello():
    return "Welcome to the public route!\n"
