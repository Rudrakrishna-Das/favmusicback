from flask import Flask,request,jsonify,make_response
from helper_functions import Helper
from flask_cors import CORS
from database import Db
import bcrypt
import jwt
import os
from dotenv import load_dotenv
from random import randint
from bson import ObjectId

load_dotenv()

app = Flask(__name__)
CORS(app)

db = Db()
helper = Helper()
feedback = helper.feedback
verify_user = helper.verify_user

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
    res.set_cookie('token',encoded_jwt,samesite='None',secure=True,path='/')
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
@app.route('/update-user',methods=['POST'])
def update_user():
    token = request.cookies.get('token')
    if token is None:
        return jsonify(feedback(False,401,'Unauthorized.'))
        
    valid = verify_user(token)
    if valid is None:
        return jsonify(feedback(False,401,'Unauthorized.'))
    
    filter = {'_id':ObjectId(valid['id'])}
    data = request.json

    if len(data) == 0:
        return jsonify(feedback(False,400,'Nothing to update'))
    if 'password' in data and len(data['password']) < 8:
        return jsonify(feedback(False,400,'Password must be 8 characters long.'))
    
    user = db.user.find_one(filter)
    if user is None:
        return jsonify(feedback(False,400,'Something went wrong'))
    
    chnaged_data = {}

    for key in data:
        if data[key] != user[key]:
            chnaged_data[key] = data[key]

    if 'password' in data:
        chnaged_data['password'] = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

    if 'email' in chnaged_data.keys():
        email_filter = {'email':chnaged_data['email']}
        email_found = db.user.find_one(email_filter)
        if email_found != None:
            return jsonify(feedback(False,400,'Email alredy exist please try another'))
    
    data_changed = bool(chnaged_data)
    del user['password']
    del user['_id']
    if data_changed:       
        db.user.update_one(filter,{'$set':chnaged_data})
        updated_user = db.user.find_one(filter)
        del updated_user['_id']
        del updated_user['password']
        print(updated_user)
        return jsonify(feedback(True,201,'Updated Successfully',updated_user))
    else :
        return jsonify(feedback(False,400,'You have Nothing to update'))

@app.route('/sign-out')
def sign_out():
    token = request.cookies.get('token')
    if token is None:
        return jsonify(feedback(False,401,'Unauthorized.'))
        
    valid = verify_user(token)
    if valid is None:
        return jsonify(feedback(False,401,'Unauthorized.'))
    res = jsonify(feedback(True,200))
    res.set_cookie('token','',max_age=0,samesite='None')
    return res


    
 

        






   


app.run(debug=True)

