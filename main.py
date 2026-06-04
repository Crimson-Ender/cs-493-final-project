from flask import Flask, request, jsonify
from google.cloud import datastore, storage
import uuid
import os

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
client = datastore.Client()
BUCKET_NAME = "PLACEHOLDER"


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
ERR_COURSE_NOT_FOUND = ({"Error": "No course with this course_id exists"},404)
ERR_MISSING_ATTRS = ({'Error':'The request body is missing at least one of the required attributes'},400)
ERR_FORBIDDEN = ({'Error':"You are not authorized to access this resource"},403)
ERR_NOT_JSON= ({'Error':'"Bad request: Body must be JSON"'},400)
ERR_BAD_METHOD = ({"Error":"Method not recognized"},405)
ERR_BAD_INSTRUCTOR_ID = ({"Error": "The value of instructor_id is invalid"},409)
ERR_UNAUTHORIZED = ({"Error":"Invalid jwt!"},401)
ERR_USER_NOT_FOUND=({"Error":"No user with this id exists"},404)
ERR_MISSING_FILE = ({"Error":"The request body is missing the file key"},400)

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
@app.route('/' + USERS + "/<int:id>", methods=["GET"])
def get_user(id):
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify(e.error), e.status_code

    sub = payload['sub']  # you were missing this line

    # get the requesting user
    query = client.query(kind=USERS)
    query.add_filter('sub', '=', sub)
    query_results = list(query.fetch())
    is_admin = bool(query_results) and query_results[0].get('role') == 'admin'  # fixed logic bug

    # get the target user being requested
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)

    if user is None:
        ERR_USER_NOT_FOUND

    # allow if admin OR if the jwt belongs to the requested user
    is_own_account = user.get('sub') == sub

    if not is_admin and not is_own_account:
        return jsonify(ERR_FORBIDDEN), 403

    result = dict(user)
    result['id'] = id
    result['self'] = request.host_url + USERS + '/' + str(id)
    return jsonify(result), 200



#create or update a user's avatar, requires matching jwt
@app.route("/"+USERS+"<int:id>/avatar", methods=['POST'])
def post_user_avatar(id):
    #check if the file is there
    if 'file' not in request.files:
        return ERR_MISSING_FILE
    
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify(e.error), e.status_code
    
    sub = payload['sub']

    user_key = client.key(USERS,id)
    user = client.get(key=user_key)

    if user is None or user.get('sub')!=sub:
        return ERR_FORBIDDEN
    
    #upload files
    file = request.files['file']
    random_filename = str(uuid.uuid4()) + '.png'
    storage_client = storage.Client()
    bucket = storage_client.bucket(BUCKET_NAME)

    #delete old avatar if one exists
    if user.get('avatar_filename'):
        old_blob = bucket.blob(user['avatar_filename'])
        if old_blob.exists():
            old_blob.delete()

    #upload the new avatar
    blob = bucket.blob(random_filename)
    blob.upload_from_file(file, content_type = 'image/png')

    user['avatar_filename'] = random_filename
    client.put(user)

    #return the avatar url

    avatar_url = request.host_url + USERS + '/' + str(id) + '/avatar'
    return jsonify({'avatar_url':avatar_url}) ,200



#get a user's avatar. requires matching jwt
@app.route('/'+USERS+'<int:id>/avatar',methods=['GET'])
def get_user_avatar(id):
    #check the user's jwt
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify(e.error), e.status_code
    
    sub = payload['sub']

    user_key = client.key(USERS,id)
    user = client.get(key=user_key)

    if user is None or user.get('sub') != sub:
        return ERR_FORBIDDEN
    if not user.get('avatar_filename'):
        return jsonify({"Error":"No avatar found"}),404
    
    storage_client = storage.Client()
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(user['avatar_filename'])

    file_data = blob.download_as_bytes()
    return file_data, 200, {'Content-Type':'image/png'}

#delete a user's avatar, requires matching jwt
@app.route('/'+USERS+"/<int:id>/avatar",methods=['DELETE'])
def delete_user_avatar(id):
    #check the user's jwt
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return jsonify(e.error), e.status_code
    
    sub = payload['sub']

    user_key = client.key(USERS,id)
    user = client.get(key=user_key)

    if user is None or user.get('sub') != sub:
        return ERR_FORBIDDEN
    if not user.get('avatar_filename'):
        return jsonify({"Error":"No avatar found"}),404
    
    storage_client = storage.Client()
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(user['avatar_filename'])
    blob.delete()

    del user['avatar_filename']
    client.put(user)

    return '',204

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
            'subject','number','title','term','instructor_id'
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
        
        new_course = datastore.entity.Entity(key=client.key(COURSES))
        new_course.update({
            "subject":content['subject'],
            'number':content['number'],
            'title':content['title'],
            'term':content['term'],
            'instructor_id':content['instructor_id'],
            'enrollment':content['enrollment']
        })
        
        client.put(new_course)
        result = dict(new_course)
        result['id'] = new_course.key.id
        result['self'] = request.host_url + COURSES + '/' + str(new_course.key.id)

        return(jsonify(result),201)

    else:
        return ERR_BAD_METHOD
        


#get a list of all courses, unprotected
#requires pagination, page size of 3 entries
#does not return enrollment data
@app.route('/'+COURSES, methods=['GET'])
def get_courses():
    #try to get jwt but don't require it
    if request.method == 'GET':

        query = client.query(kind=COURSES)
        query_results = list(query.fetch())
        courses = []
        for course in query_results:
            c = dict(course)
            c['id'] =course.key.id
            c['self'] - request.host_url + COURSES + '/' + str(course.key.id)
            c.pop('enrollment',None)
            courses.append(c)

        return jsonify(courses),200

#get information about a single course, unprotected
#does not return enrollment data
@app.route("/"+COURSES+"<int:id>",methods=['GET'])
def get_single_course(id):
    #try to get jwt but don't require it

    if request.method == 'GET':

        course_key  = client.key(COURSES,id)
        course = client.get(key=course_key)

        #check if the course is existent
        if course is None:
            ERR_COURSE_NOT_FOUND
        else:
            #if the course is properly retrieved, return it

            result = dict(course)
            result['id'] = id
            result['self'] = request.host_url + COURSES + '/' + str(id)
            return(jsonify(result),200)

#update course data, requires admin login
@app.route('/'+COURSES+'<int:id>',methods=['PATCH'])
def update_course_data(id):
        
    if request.method == "PATCH":
        try:

            payload = verify_jwt(request)
        except Exception:
            return ERR_FORBIDDEN
        
        sub = payload['sub']

        #check if the course exists
        course_key = client.key(COURSES,id)
        course = client.get(course_key)

        #check if the user is an admin
        query = client.query(kind=USERS)
        query.add_filter('sub','=',sub)
        query_results = list(query.fetch())
        is_admin = bool(query_results) and query_results[0].get('role') == 'admin'

        #if not admin, throw a forbidden error
        if not course or not is_admin:
            return ERR_FORBIDDEN
        
        content=request.get_json()
        if not content:
            #empty body is valid, that means there is nothing to be validated
            c = dict(course)
            c['id'] = course.key.id
            c['self'] = request.host_url + COURSES + '/' + str(id)
            return jsonify(c),200
        
    #validate instructor_id if provided (409)
    if 'instructor_id' in content:
        instructor_key = client.key(USERS, content['instructor_id'])
        instructor = client.get(instructor_key)
        if not instructor or instructor.get('role') != 'instructor':
            return jsonify(ERR_BAD_INSTRUCTOR_ID),409
        
    allowed_fields = {'subject','number','title','term','instructor_id'}
    for field in allowed_fields:
        if field in content:
            course[field] = content[field]
    
    client.put(course)

    #convert to dict and return response
    course_dict = dict(course)
    course_dict['id'] = course.key.id
    course_dict['self'] = request.host_url + COURSES + '/' + str(id)
    
    return jsonify(course_dict),200

#delete a course, requires admin login
@app.route('/'+COURSES+'<int:id>',methods=['DELETE'])
def delete_course(id):
    if request.method == "DELETE":
        payload = verify_jwt(request)
        sub = payload['sub']

        #check if the course exists
        course_key = client.key(COURSES,id)
        course = client.get(course_key)

        #check if the user is an admin
        query = client.query(kind=USERS)
        query.add_filter('sub','=',sub)
        query_results = list(query.fetch())
        is_admin = bool(query_results) and query_results[0].get('role') == 'admin'

        #if the course does not
        if course is None:
            return ERR_COURSE_NOT_FOUND
        
        else:        
            #if the course exists, check if the user is either an admin or the cours owner
            if not is_admin:
                return ERR_FORBIDDEN
            else:
                client.delete(course_key)
                return('',204)

#update enrollment of a course. Requires either a admin login, or for your jwt to correspond to the course owner.
app.route('/'+COURSES+"<int:id>/students",methods=['PATCH'])
def update_course_enrollment(id):
    if request.method == "PATCH":
        payload = verify_jwt(request)
        sub = payload['sub']

        #check if the course exists
        course_key = client.key(COURSES,id)
        course = client.get(course_key)

        if course is None:
            return ERR_COURSE_NOT_FOUND
        
        else:

            #check iof the user is admin
            query = client.query(kind=USERS)
            query.add_filter('sub','=',sub)
            query_results = list(query.fetch())
            is_admin = bool(query_results) and query_results[0].get('role') == 'admin'

            #check if the user is either an admin or the owner of the course
            if not is_admin or (course['instructor_id']!=sub):
                return ERR_FORBIDDEN
            else:
                content = request.get_json()
                
                #if there is no content, just return the course as is
                if not content:
                    #empty body is valid, that means there is nothing to be validated
                    c = dict(course)
                    c['id'] = course.key.id
                    c['self'] = request.host_url + COURSES + '/' + str(id)
                    return jsonify(c),200
                

                course['enrollment'] = content['enrollment']
                client.put(course)

                #convert to dict and return response
                c = dict(course)
                c['id'] = course.key.id
                c['self'] = request.host_url + COURSES + '/' + str(id)
                
                return jsonify(c),200

#get enrollment of a course. Requires either an admin login, or for the jwt to match that of the course owner
app.route('/'+COURSES+"<int:id>/students",methods=['GET'])
def get_course_enrollment(id):
    if request.method == "GET":
        try:
            payload = verify_jwt(request)
        except Exception:
            return ERR_UNAUTHORIZED
        
        sub = payload['sub']

        course_key = client.key(COURSES,id)
        course = client.get(course_key)

        if course is None:
            return ERR_COURSE_NOT_FOUND

        #check if the user is an admin
        query = client.query(kind=USERS)
        query.add_filter('sub','=',sub)
        query_results = list(query.fetch())
        is_admin = bool(query_results) and query_results[0].get('role') == 'admin'

        #check if the user is an admin 
        #check if the user is either an admin or the owner of the course
        if not is_admin or (course['instructor_id']!=sub):
            return ERR_FORBIDDEN
        
        enrollment = course.get('enrollment',[])
        return jsonify(enrollment),200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)