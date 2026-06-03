from flask import Flask, request, jsonify
from google.cloud import datastore
import os

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
client = datastore.Client()


#fetch the three environment variables
CLIENT_ID = os.environ.get("CLIENT_ID","ENV_CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET","ENV_CLIENT_SECRET")
DOMAIN = os.environ.get("DOMAIN","ENV_DOMAIN")

ALGORITHMS = ["RS256"]

#routing constants
COURSES = "courses"
USERS= "users"

#error messages
ERR_BUS_NOT_FOUND = ({"Error": "No business with this business_id exists"}, 403)
ERR_MISSING_ATTRS = ({'Error':'The request body is missing at least one of the required attributes'},400)
ERR_FORBIDDEN = ({'Error':"You are not authorized to access this resource"},403)
ERR_NOT_JSON= ({'Error':'"Bad request: Body must be JSON"'},400)

oauth = OAuth(app)

#authorize users, set up Auth0 integration

auth0 = oauth.register(
    'auth0',
    client_id = CLIENT_ID,
    client_secret = CLIENT_SECRET,
    api_base_url = "https://" + DOMAIN,
    access_token_url = "https://" + DOMAIN + "oauth/token",
    authorize_url = "https://" + DOMAIN + "/authorize",
    client_kwargs = {
        'scope':'openid profile email'
    }
)

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(excep):
    response = jsonify(excep.error)
    response.status_code = excep.status_code
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
    
#index route
@app.route('/')
def index():
    return "Please navigate to /users or /courses to use this API"

#login users with pre-created Auth0 user account, with username and password
@app.route('/'+USERS+"/login",methods=['POST'])
def user_login():
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

@app.route('/decode',methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload

#get a summary of all users, only accessible when logged in as an admin user
@app.route('/'+USERS,methods=['GET'])
def get_all_users():

    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify(e.error), e.status_code
    
    sub = payload['sub']

    #check if the user is an admin
    query = client.query(kind=USERS)
    query.add_filter('sub','=',sub)
    query_results = list(query.fetch())

    if not query_results or query_results[0].get('role') != "admin":
        return ERR_FORBIDDEN
    
    #return summary of all of the users
    all_users_query = client.query(kind=USERS)
    all_users_result = list(all_users_query.fetch())

    users = []

    for entity in all_users_result:
        users.append({
            'id':entity.key.id,
            'role':entity.get('role'),
            'sub':entity.get('sub')
        })
    
    return jsonify(users), 200
    

#get a user. works either as an admin, with an admin token, or if you have the jwt that matches the user
@app.route('/'+USERS+ "/<int:id>", methods=["GET"])
def get_user(id):
    pass

#create or update a user's avatar, requires matching jwt
@app.route("/"+USERS+"<int:id>/avatar")
def post_user_avatar(id):
    pass

#get a user's avatar. requires matching jwt
@app.route('/'+USERS+'<int:id>/avatar',methods=['GET'])
def get_user_avatar(id):
    pass

#delete a user's avatar, requires matching jwt
@app.route('/'+USERS+"/<int:id>/avatar",methods=['DELETE'])
def delete_user_avatar(id):
    pass

"""
course schema = 
{
subject, number, title, term, instructor_id
}

"""

#create a course, can only be used by an admin user
@app.route('/'+COURSES, methods=['POST'])
def create_course():

    if request.method == 'POST':
        content = request.get_json()

        #validate inputs
        if content is None:
            return ERR_NOT_JSON
        
        required_fields = [
            'subject','number','title','term'
        ]

        missing_fields = [
            field for field in required_fields
            if field not in content or content[field] in [None,'']
        ]

        if missing_fields:
            return ERR_MISSING_ATTRS
        
        payload = verify_jwt(request)
        sub = payload['sub']

        #check if the user is an admin
        query = client.query(kind=USERS)
        query.add_filter('sub','=',sub)
        query_results = list(query.fetch())

        if not query_results or query_results[0].get('role') != "admin":
            return ERR_FORBIDDEN
        
    else:
        return jsonify(error="Method not recognized")
        


#get a list of all courses, unprotected
#requires pagination, page size of 3 entries
#does not return enrollment data
@app.route('/'+COURSES, methods=['GET'])
def get_courses():
    return

#get information about a single course, unprotected
#does not return enrollment data
@app.route("/"+COURSES+"<int:id>",methods=['GET'])
def get_single_course(id):
    return

#update course data, requires admin login
@app.route('/'+COURSES+'<int:id>',methods=['PATCH'])
def update_course_data(id):
    return

#delete a course, requires admin login
@app.route('/'+COURSES+'<int:id>',methods=['DELETE'])
def delete_course(id):
    return

#update enrollment of a course. Requires either a admin login, or for your jwt to correspond to the course owner.
app.route('/'+COURSES+"<int:id>/students",methods=['PATCH'])
def update_course_enrollment(id):
    return

#get enrollment of a course. Requires either an admin login, or for the jwt to match that of the course owner
app.route('/'+COURSES+"<int:id>/students",methods=['GET'])
def get_course_enrollment(id):
    return

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)