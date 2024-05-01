from flask import Flask,request,jsonify,make_response
from helper_functions import Helper
from flask_cors import CORS
from database import Db
import bcrypt
import jwt
import os
from dotenv import load_dotenv
from random import randint

load_dotenv()

app = Flask(__name__)
CORS(app)

db = Db()
helper = Helper()
feedback = helper.feedback

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response


@app.route('/sign-up',methods=['POST'])
def sign_up():
    data = request.json
    if len(data['userName']) < 2:
        return jsonify(feedback(False,400,'Username must be greater than 2 characters'))
    if len(data['email']) == 0:
        return jsonify(feedback(False,400,'Email can not be empty'))
    if len(data['password']) < 8:
        return jsonify(feedback(False,400,'Password atleast be 8 characters')) 
    user = db.user.find_one({'email':data['email']})
    if user is not None:
        return jsonify(feedback(False,403,'Account already exist with this email.'))
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'),bcrypt.gensalt())
    db.user.insert_one({'userName':data['userName'],'email':data['email'],'password':hashed_password,'avatar':"https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png"})
    return jsonify(feedback(True,201))


@app.route('/sign-in',methods=['POST'])
def sign_in():
    data = request.json
    if len(data['email']) == 0:
        return jsonify(feedback(False,400,'Email can not be empty'))
    if len(data['password']) < 8:
        return jsonify(feedback(False,400,'Password too short')) 
    user = db.user.find_one({'email':data['email']})
    if user is None:
        return jsonify(feedback(False,403,'Please check your email.'))
    password = bcrypt.checkpw(data['password'].encode('utf-8'),user['password'])
    if password == False:
        return jsonify(feedback(False,403,'Please check your password.'))
    del user['password']
    user['_id'] = str(user['_id'])
    encoded_jwt = jwt.encode({"id": str(user['_id'])}, os.getenv('SECRET') , algorithm=os.getenv('ALOGORITHMS'))    
    
    res = make_response(jsonify(feedback(True,200,'Login Success',user)))
    res.set_cookie('token',encoded_jwt, httponly=True)
    return res

@app.route('/google',methods=['POST'])
def google():
    data = request.json
    user = db.user.find_one({'email':data['email']})
    if user:
        del user['password']
        user['_id'] = str(user['_id'])
        encoded_jwt = jwt.encode({"id": str(user['_id'])}, os.getenv('SECRET') , algorithm=os.getenv('ALOGORITHMS'))
        res = make_response(jsonify(feedback(True,200,'Login Success',user)))
        res.set_cookie('token',encoded_jwt, httponly=True)
        return res
    password = str(hex(randint(11111111,99999999)))
    hashed_password =  bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
    id = db.user.insert_one({'userName':data['userName'],'email':data['email'],'password':hashed_password,'avatar':data['avatar']})
    new_user = db.user.find_one({'_id':id.inserted_id})
    del new_user['password']
    new_user['_id'] = str(new_user['_id'])

    encoded_jwt = jwt.encode({"id": str(new_user['_id'])}, os.getenv('SECRET') , algorithm=os.getenv('ALOGORITHMS'))    
    
    res = make_response(jsonify(feedback(True,200,'Login Success',new_user)))
    res.set_cookie('token',encoded_jwt, httponly=True)
    return res
    






   


app.run(debug=True)

