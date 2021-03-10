from datetime import date
from flask import Flask, request, jsonify, make_response
from flask_restful import Resource, Api
from functools import wraps
import jwt
import bcrypt
import datetime
from random import randint

from flask_mail import Mail, Message
from pymongo import MongoClient

app = Flask(__name__)
api = Api(app)


app.config["SECRET_KEY"] = "thisi-sth(esecret_key"
# mail thing here
app.config['MAIL_SERVER']='smtp.yandex.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
# mail end here

client = MongoClient("mongodb://db:27017")
mail = Mail(app)
# client = MongoClient('localhost', 27017)
# client = MongoClient('mongodb://localhost:27017/')

# app.config["MONGO_URI"] = "mongodb://localhost:27017/myDatabase"
# mongo = PyMongo(app)

db = client.Users
users = db["Users"]  # making collections

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get("token") # http://127.0.0.1:5000/route?token=sdasdasdaqwesadaw
        if not token:
            return jsonify({"msg" : "Token is missing!", "status": 402})

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])

        except:
            return jsonify({"msg" : "Token is invalid!", "status": 403})

        return f(*args, **kwargs)

    return decorated

def UserExist(username):
    if users.find({"username": username}).count() == 0:
        return False
    else: 
        return True

def EmailExist(email):
    if users.find({"email": email}).count() == 0:
        return False
    else: 
        return True

def verifyPw(username, password):
    if not UserExist(username):
        return False

    hashed_pw = users.find({
        "username": username
    })[0]["password"]

    if bcrypt.hashpw(password.encode("utf8"), hashed_pw) == hashed_pw:
        return True
    else:
        return False

def verifyPwWithEmail(email, password):
    if not EmailExist(email):
        return False

    hashed_pw = users.find({
        "email": email
    })[0]["password"]

    if bcrypt.hashpw(password.encode("utf8"), hashed_pw) == hashed_pw:
        return True
    else:
        return False

def updateVerificationCode(email):
    code = users.find({
            "email": email
        })[0]["verification_code"]

    generated_code = randint(10000, 99999)
    
    users.update({"verification_code" : code}, {"$set" : {"verification_code": generated_code}})

    return generated_code


def GetCodeFromDb(email):
    code = users.find({
            "email": email
        })[0]["verification_code"]
    print("Code Here : ", code)
    return code

def setNewPassword(email, updated_password):
    password = users.find({
            "email": email
        })[0]["password"]
    
    users.update({"password" : password}, {"$set" : {"password": updated_password}})    

class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        contact = postedData["contact_num"]
        email = postedData["email"]
        age = postedData["age"]
        gender = postedData["gender"]

        if username and password and email:
            if UserExist(username):
                retJson = {
                    "status" : 301,
                    "msg" : "Username already exists"
                }
                return jsonify(retJson)
            
            if EmailExist(email):
                retJson = {
                    "status" : 302,
                    "msg" : "Email is already registered"
                }
                return jsonify(retJson)
            
            hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # store username and password in the database
        # if username and password:
            token = jwt.encode({"user" : username, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config["SECRET_KEY"])
            
            users.insert({
                "username": username,
                "password": hashed_pw,
                "contact_num": contact,
                "email": email,
                "age": age,
                "gender": gender,
                "Token" : token,
                "verification_code": 0
            })
            retJson = {
                "Token": token.decode('UTF-8'),
                "status" : 200
            }

            return jsonify(retJson)
        
        retJson = {
            "status" : 303,
            "msg" : "Please fill all the fields."
        }
        return jsonify(retJson)

class Login(Resource):
    def post(self):
        postedData = request.get_json()

        # username = postedData["username"]
        email = postedData["email"]
        password = postedData["password"]
        
        if email and password:
            correct_pw = verifyPwWithEmail(email, password)

            if not correct_pw:
                retJson = {
                    "status" : 301,
                    "msg" : "Invalid Password"
                }
                return jsonify(retJson)

            
            token = jwt.encode({"user" : email, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, app.config["SECRET_KEY"])
            
            retJson = {
                "Token" : token.decode('UTF-8'),
                "status" : 200
            }

            return jsonify(retJson)

        retJson = {
            "msg" : "Fields can not be empty. Login required!",
            "status" : 401
        }
        return jsonify(retJson)

class ForgetPass(Resource):
    def post(self):
        postedData = request.get_json()

        email = postedData["email"]
        new_password = postedData["newPassword"]
        confirm_password = postedData["confirmPassword"]
        code = postedData["code"]

        if email and new_password and confirm_password and code:

            if new_password != confirm_password:
                retJson = {
                    "msg": "Password doesn't match!",
                    "status" : 301 
                }
                return jsonify(retJson)

            db_code = GetCodeFromDb(email)

            if db_code != code:
                retJson = {
                    "msg": "The code didn't match!",
                    "status" : 302 
                }
                return jsonify(retJson)
            
            hashed_password = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())
            setNewPassword(email, hashed_password)

            retJson = {
                "msg" : "Password updated successfully.",
                "status" : 200
            }
            return jsonify(retJson)

        retJson = {
            "message" : "Please fill all the fields",
            "status" : 303
        }
            
        return retJson


class SendVerificationCode(Resource):
    def post(self):
        postedData = request.get_json()
        email = postedData["email"]
        
        if email:
            if not EmailExist(email):
                retJson = {
                    "msg" : "No such registered email",
                    "status" : 303
                }
                return jsonify(retJson)

            code = updateVerificationCode(email)
            msg = Message('Covid Tracker: {}'.format(code), sender = 'furqan4545@yandex.ru', recipients = [email])
            msg.body = "Here is your verification code: {}".format(code)
            mail.send(msg)

            retJson = {
                "msg": "Email has been sent to the registered email",
                "status" : 200
            }            
            return jsonify(retJson)

        retJson = {
            "msg": "Email field can't be empty!",
            "status": 302
        }
        return jsonify(retJson)


@app.route("/protected")
@token_required
def protected():
    return jsonify({"msg": "This is only available to people with valid token!"})


api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(SendVerificationCode, '/sendcode')
api.add_resource(ForgetPass, '/resetpass')


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5000)




