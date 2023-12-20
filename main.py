from google.cloud import datastore
from flask import Flask, request, jsonify
import requests
import constants

from functools import wraps
import json

from urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt


import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from urllib.parse import quote_plus, urlencode

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

# CONSTANTS FOR ENTITIES
BACKLOGS = "backlogs"
GAMES = "games"

# Update the values of the following 3 variables - reused from assignment 7
CLIENT_ID = constants.CLIENT_ID
CLIENT_SECRET = constants.CLIENT_SECRET
DOMAIN = constants.DOMAIN
# For example
# DOMAIN = 'fall21.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url='https://' + DOMAIN + '/.well-known/openid-configuration'
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /home to use this API"

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type':'application/json'}


# Auth0 shennanagins - https://auth0.com/docs/quickstart/webapp/python
@app.route("/create")
def create():
    nonce = generate_nonce()
    session['nonce'] = nonce

    return oauth.auth0.authorize_redirect(
        redirect_uri = url_for("callback", _external=True),
        nonce = nonce
    )

def generate_nonce():
    import secrets
    return secrets.token_urlsafe(16)


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    nonce = session.get('nonce')
    user_info = oauth.auth0.parse_id_token(token, nonce=nonce)
    store_user(user_info)
    session["user"] = token
    return redirect("/home")

def store_user(user_info):
    user_id = user_info.get("sub")
    username = user_info.get("nickname")

    user_entity = datastore.Entity(key=client.key('User', user_id))
    user_entity.update({
        'username': username
    })

    client.put(user_entity)
    return


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + DOMAIN
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": CLIENT_ID,
            },
            quote_via=quote_plus,
        )
    )


@app.route("/home")
def home():
    return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))

# Unprotected GET /users that shows all users
@app.route('/users', methods=['GET'])
def get_all_users():

    if 'Accept' not in request.headers or 'application/json' not in request.headers['Accept']:
        return {"Error": "Unsupported media type."}, 406

    # Query all user entities from Datastore
    query = client.query(kind='User')
    users = list(query.fetch())

    # Extract relevant information for display
    users_data = [{'id': user.key.name, 'username': user['username']} for user in users]

    # Return the users as JSON
    return jsonify(users_data), 200, {'Content-Type': 'application/json'}


# Write CRUD for 2 non-user entities - Backlogs (user-tied) and Games (Many-to-One with Backlogs)
@app.route('/backlogs', methods=['GET', 'POST']) # User-tied
# Properties: id, self, platform(string), gamelist, date_created(string), time(int: default 0)
def backlogs_post_get():
    # POST: required platform and date_created. Gamelist is empty list. Time is 0. id and self are auto-created.
    # Time will be inreased by a game's time_to_beat when the game is added to the list.

    if 'Accept' not in request.headers or 'application/json' not in request.headers['Accept']:
        return {"Error": "Unsupported media type."}, 406

    if request.method == 'POST':
        payload = verify_jwt(request)
        user_info = payload["sub"]
        content = request.get_json()
        if "platform" in content and "date_created" in content:
            new_backlog = datastore.entity.Entity(key=client.key(BACKLOGS))
            new_backlog.update({"platform": content["platform"], "gamelist": [], "date_created": content["date_created"], "time": 0, "owner": user_info})
            client.put(new_backlog)
            new_backlog_id = new_backlog.key.id
            new_backlog.update({"id": new_backlog_id})
            new_backlog_url = request.host_url + "backlogs/" + str(new_backlog_id)
            new_backlog["self"] = new_backlog_url
            client.put(new_backlog)
            return (new_backlog, 201)
        else:
            error_response = {"Error": "The request object is missing at least one of the required attributes"}
            return error_response, 400

    # GET: Shows all backlogs for the user, paginated to show 5 at a time.
    elif request.method == 'GET':
        payload = verify_jwt(request)
        user_info = payload["sub"]

        page = request.args.get('page', default = 1, type = int)
        per_page = 5

        backlogs_query = client.query(kind=BACKLOGS)
        backlogs_query.add_filter("owner", "=", user_info)

        total_backlogs = len(list(backlogs_query.fetch()))
        user_backlogs = list(backlogs_query.fetch(limit=per_page, offset=(page - 1) * per_page))

        response = [
            {
                "id": backlog.key.id,
                "self": backlog["self"],
                "platform": backlog["platform"],
                "gamelist": backlog["gamelist"],
                "date_created": backlog["date_created"],
                "time": backlog["time"],
                "owner": backlog["owner"]
            }
            for backlog in user_backlogs
        ]

        if len(user_backlogs) == per_page:
            next_page = page + 1
        else:
            next_page = None

        if next_page is not None:
            next_link = url_for('backlogs_post_get', page=next_page, _external=True)
            response.append({"next": next_link})

        response.append({"total_count": total_backlogs})
        return jsonify(response), 200

    else:
        return {"Error": "Method not allowed"}, 405


@app.route('/backlogs/<backlog_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def backlogs_get_put_delete(backlog_id):

    if 'Accept' not in request.headers or 'application/json' not in request.headers['Accept']:
        return {"Error": "Unsupported media type."}, 406

    # Verify backlog is real and belongs to user for all methods
    payload = verify_jwt(request)
    user_info = payload["sub"]

    backlog_key = client.key(BACKLOGS, int(backlog_id))
    backlog = client.get(backlog_key)

    if backlog is not None and backlog["owner"] == user_info:
        # GET: Shows the backlog with the specified ID as long as it belongs to the user
        if request.method == 'GET':
            backlog["id"] = backlog.key.id
            game_titles = []
            for game_id in backlog["gamelist"]:
                game_key = client.key(GAMES, int(game_id))
                game = client.get(game_key)
                if game:
                    game_titles.append(game["title"])
            backlog["gamelist"] = game_titles
            return backlog, 200

        # PUT: Edit the backlog with the specified ID as long as it belongs to the user
        elif request.method == 'PUT' or request.method == 'PATCH':
            content = request.get_json()
            if "platform" in content and "date_created" in content:
                backlog.update({
                    "platform": content["platform"],
                    "date_created": content["date_created"]
                })
                client.put(backlog)
                return backlog, 200

            else:
                error_response = {"Error": "The request object is missing at least one of the required attributes"}
                return error_response, 400

        # DELETE: Deletes the backlog with the specified ID as long as it belongs to the user
        elif request.method == 'DELETE':
            client.delete(backlog_key)
            return "", 204

        else:
            return {"Error": "Method not allowed"}, 405
        
    elif backlog is None:
        return {"Error": "Backlog not found"}, 404
    else:
        return {"Error": "Backlog does not belong to the user"}, 403


@app.route('/games', methods=['GET', 'POST']) # Not User-tied
# Properties: id, self, title(string), time_to_beat(int), developer(string)
def games_post_get():

    if 'Accept' not in request.headers or 'application/json' not in request.headers['Accept']:
        return {"Error": "Unsupported media type."}, 406

    if request.method == 'POST':
        content = request.get_json()
        if "title" in content and "time_to_beat" in content and "developer" in content:
            new_game = datastore.entity.Entity(key=client.key(GAMES))
            new_game.update({"title": content["title"], "time_to_beat": content["time_to_beat"], "developer": content["developer"]})
            client.put(new_game)
            new_game_id = new_game.key.id
            new_game.update({"id": new_game_id})
            new_game_url = request.host_url + "games/" + str(new_game_id)
            new_game["self"] = new_game_url
            client.put(new_game)
            return new_game, 201

        else:
            error_response = {"Error": "The request object is missing at least one of the required attributes"}
            return error_response, 400

    # Return all games with pagination of 5 per page
    elif request.method == 'GET':
        page = request.args.get('page', default=1, type=int)
        per_page = 5

        games_query = client.query(kind=GAMES)
        total_games = len(list(games_query.fetch()))
        games = list(games_query.fetch(limit=per_page, offset=(page-1) * per_page))

        response = [
            {
                "id": game.key.id,
                "self": game["self"],
                "title": game["title"],
                "time_to_beat": game["time_to_beat"],
                "developer": game["developer"]
            }
            for game in games
        ]

        if len(games) == per_page:
            next_page = page + 1
        else:
            next_page = None

        if next_page is not None:
            next_link = url_for('games_post_get', page=next_page, _external=True)
            response.append({"next": next_link})

        response.append({"total_count": total_games})
        return jsonify(response), 200


    else:
        return {"Error": "Method not allowed"}, 405



@app.route('/games/<game_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def games_get_put_delete(game_id):

    if 'Accept' not in request.headers or 'application/json' not in request.headers['Accept']:
        return {"Error": "Unsupported media type."}, 406

    game_key = client.key(GAMES, int(game_id))
    game = client.get(game_key)

    if game is None:
        return {"Error": "Game not found"}, 404

    if request.method == 'GET':
        return game, 200

    elif request.method == 'PUT' or request.method == 'PATCH':
        content = request.get_json()
        if "title" in content and "time_to_beat" in content and "developer" in content:
            old_time_to_beat = game["time_to_beat"]
            game.update({
                "title": content["title"],
                "time_to_beat": content["time_to_beat"],
                "developer": content["developer"]
            })
            client.put(game)

            backlogs_query = client.query(kind=BACKLOGS)
            backlogs = list(backlogs_query.fetch())

            for backlog in backlogs:
                if game.key.id in backlog["gamelist"]:
                    backlog["time"] += (game["time_to_beat"] - old_time_to_beat)
                    client.put(backlog)

            return game, 200
        else:
            error_response = {"Error": "The request object is missing at least one required attribute"}
            return error_response, 400

    elif request.method == 'DELETE':
        backlogs_query = client.query(kind=BACKLOGS)
        backlogs = list(backlogs_query.fetch())

        for backlog in backlogs:
            if game.key.id in backlog["gamelist"]:
                backlog["gamelist"].remove(game.key.id)
                backlog["time"] -= game["time_to_beat"]
                client.put(backlog)

        client.delete(game_key)
        return "", 204

    else:
        return {"Error": "Method not allowed"}, 405


# Add relational endpoints below
@app.route('/backlogs/<backlog_id>/games/<game_id>', methods = ['POST', 'DELETE'])
def game_backlog_relation(backlog_id, game_id):

    if 'Accept' not in request.headers or 'application/json' not in request.headers['Accept']:
        return {"Error": "Unsupported media type."}, 406

    payload = verify_jwt(request)
    user_info = payload["sub"]

    backlog_key = client.key(BACKLOGS, int(backlog_id))
    game_key = client.key(GAMES, int(game_id))

    backlog = client.get(backlog_key)
    game = client.get(game_key)

    if backlog is None:
        return {"Error": "Backlog not found"}, 404
    elif game is None:
        return {"Error": "Game not found"}, 404
    elif backlog["owner"] != user_info:
        return {"Error": "Backlog does not belong to the user"}, 403
    else:
        # Add the game to the backlog's gamelist attribute. Increase the backlog's time attribute by the game's time_to_beat attribute.
        if request.method == 'POST':
            if game.key.id not in backlog["gamelist"]:
                backlog["gamelist"].append(game.key.id)
                backlog["time"] += game["time_to_beat"]
                client.put(backlog)
                return "", 200
            else:
                return {"Error": "Game is already in the backlog"}, 400

        # Remove the game from the backlog's gamelist attribute. Decrease the backlog's time attribute by the game's time_to_beat attribute.
        elif request.method == 'DELETE':
            if game.key.id in backlog["gamelist"]:
                backlog["gamelist"].remove(game.key.id)
                backlog["time"] -= game["time_to_beat"]
                client.put(backlog)
                return "", 200
            else:
                return {"Error": "Game is not in the backlog"}, 400
        else:
            return "Method not recognized"


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
