from flask import Flask, g, request, send_file, send_from_directory, Response, jsonify
import requests
import sys
import os
import json
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from dotenv import load_dotenv
load_dotenv()
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
app.config["JWT_ALGORITHM"] = "HS256" 
app.config["MONGO_URI"] = os.environ.get("MONGO_URI")

client = MongoClient(os.environ.get("MONGO_URI"))

db = client[os.environ.get("MONGO_DATABASE")]

# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@app.route("/login", methods=["POST"])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    #Check if hash from db doesn't match with current password given
    hashFromDB = db.users.find_one({"email": email})["password"]
    if not bcrypt.check_password_hash(hashFromDB, password):
        return jsonify({"message": "Bad email or password"}), 401

    access_token = create_access_token(identity=email)
    return jsonify(access_token=access_token)

@app.route("/register", methods=["POST"])
def register():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    screenName = request.json.get("screenName", "")

    passwordHash = bcrypt.generate_password_hash(password).decode('utf-8') 
    #Check if email is already taken
    if not db.users.find_one({"email": email}):
        db.users.insert_one({"screenName": screenName, "email": email, "password": passwordHash, "friends": []}).inserted_id
        access_token = create_access_token(identity=email)

        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Email already exists"}), 401

if __name__ == '__main__':
    app.run(debug=True)