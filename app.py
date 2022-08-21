import jwt
from flask import Flask, request, render_template

SECRET = "aeradie7queig3eiR7saido9ujohzuzohngahpah"
app = Flask(__name__)


def create_jwt(body):
    return jwt.encode(body, SECRET, algorithm="HS256")


def decode_jwt(token):
    return jwt.decode(token, SECRET, algorithms=["HS256"])


@app.after_request
def add_header(request):
    request.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    request.headers["Pragma"] = "no-cache"
    request.headers["Expires"] = "0"
    request.headers['Cache-Control'] = 'public, max-age=0'
    return request


@app.route("/")
def home():
    """Home Page. Public page"""
    return render_template("index.html")


@app.route("/login")
def login():
    """Login Page. Frontend for the login page."""
    return render_template("login.html")


@app.route("/api/login", methods=['POST'])
def api_login():
    """API endpoint for login. Returns JWT in body."""
    # Check username and password are valid
    data = request.get_json()
    if not data:
        return {"error": "no data received"}, 403
    try:
        username = data["username"]
        password = data["password"]
    except Exception:
        return {"error": "malformed request"}, 403
    if not (username == "greg" and password == "password"):
        return {"error": "incorrect credentials"}, 403
    # Return token in body
    encoded_jwt = create_jwt({"username": "greg", "role": "user"})
    return {"token": encoded_jwt}


@app.route("/api/protected")
def api_protected():
    """Protected page contents. This stuff is retrieved by the JavaScript.
    Checks the Authorization Bearer header for token.
    If not present its redirects to login."""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return {"error": "invalid token"}, 403
    try:
        token = auth_header.split(" ")[1]
    except IndexError:
        return {"error": "invalid token"}, 403
    # Validate the JWT
    try:
        dec_token = decode_jwt(token)
    except Exception:
        return {"error": "invalid token"}, 403
    if "user" not in dec_token["role"]:
        return {"error": "no permissions"}, 403
    return {
        "content": "This is the secret content"
    }


@app.route("/protected")
def protected():
    """Protected page. This returns the HTML skeleton.
    The JS code then requests the /api/protected to fill in the contents
    using the JWT received from loggin in."""
    return render_template("protected.html")
