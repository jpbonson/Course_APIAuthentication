import datetime
from functools import wraps
from flask import request, Response, jsonify
import jwt
from jwt.api_jwt import PyJWT

secret_keys = {
    "1": "supersecret"
}


def _check_credentials(key, secret):
    return key == 'client_id' and secret == 'client_secret'


def generate_jwt_token():
    auth = request.get_json()
    if 'grant_type' not in auth:
        return Response('Must specify the type of grant\n', 400)
    if auth['grant_type'] != 'client_credentials':
        return Response('The only grant available is client_credentials\n', 400)
    if 'client_id' not in auth or 'client_secret' not in auth:
        return Response('Must provide a client_id/client_secret pair\n', 400)
    if 'audience' not in auth:
        return Response('Must provide an audience\n', 400)
    if not _check_credentials(auth['client_id'], auth['client_secret']):
        return Response('Invalid client_id/client_secret pair\n', 404)

    expires_in = 60 * 10  # 10 mins
    current_time = datetime.datetime.utcnow()
    expiration_time = current_time + datetime.timedelta(seconds=expires_in)

    kid = "1"

    token_header = {
        "alg": "HS256",
        "kid": kid
    }
    token_payload = {
        "iss": "https://course-api-auth.herokuapp.com/",
        "sub": auth['client_id'] + "@clients",
        "aud": auth['audience'],
        "exp": expiration_time,  # unix timestamp of the token expiration date
        "iat": current_time,  # unix timestamp of the token creation date
        "scope": ""
    }
    encoded_token = jwt.encode(token_payload, secret_keys[kid], algorithm='HS256', headers=token_header)

    response = {
        "access_token": encoded_token.decode("utf-8"),
        "token_type": "Bearer",
        "expires_in": expires_in
    }
    return jsonify(response)


# https://github.com/jpadilla/pyjwt/blob/master/docs/usage.rst
def _token_errors(encoded_token):
    decoded_payload, signing, header, signature = PyJWT()._load(encoded_token)
    kid = header['kid']

    issuer = "https://course-api-auth.herokuapp.com/"
    audience = issuer

    try:
        jwt.decode(
            encoded_token,
            secret_keys[kid],
            issuer=issuer,
            audience=audience,
            algorithms=['HS256']
        )
    except Exception as e:
        return str(e)

    return None


def _authenticate():
    """ Sends a 401 response with the type of auth expected """
    return Response(
        'Unauthorized, please login with the correct credentials\n', 401,
        {'WWW-Authenticate': 'Bearer'})


def requires_jwt_token_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_type = None
        token = None
        try:
            auth = request.headers['authorization']
            auth_type, token = auth.split()
        except KeyError:
            return _authenticate()
        if auth_type != 'Bearer':
            return _authenticate()
        result = _token_errors(token)
        if result:
            return Response(
                'Unauthorized, there are errors in the token: ' + result + '\n', 401,
                {'WWW-Authenticate': 'Bearer'})
        return f(*args, **kwargs)
    return decorated
