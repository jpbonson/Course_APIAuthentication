from app.basic_auth import requires_basic_auth

from flask import Flask
app = Flask(__name__)


@app.route('/basic')
@requires_basic_auth
def secret_page():
    return "Accessed using Basic authentication!\n"


@app.route("/")
def hello():
    return "Welcome to the public route!\n"
