from flask import Flask,request,jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/sign-up',methods=['POST'])
def send():
    data = request.json
    print(data)
    return 

app.run(debug=True)

