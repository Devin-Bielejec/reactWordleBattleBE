from flask import Flask, g, request, send_file, send_from_directory, Response, jsonify
from flask_restful import Resource, Api, reqparse
from requests import put, get
import requests
import sys
sys.path.insert(0, "./creatingWorksheets")
from documentCreation import createVersions
import os
import json
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from dotenv import load_dotenv
load_dotenv()
import pprint
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
        return jsonify({"msg": "Bad email or password"}), 401

    access_token = create_access_token(identity=email)
    return jsonify(access_token=access_token)

@app.route("/register", methods=["POST"])
def register():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    passwordHash = bcrypt.generate_password_hash(password).decode('utf-8') 
    #Check if email is already taken
    if not db.users.find_one({"email": email}):
        db.users.insert_one({"email": email, "password": passwordHash}).inserted_id
        access_token = create_access_token(identity=email)
        return jsonify(access_token=access_token)
    else:
        return jsonify({"msg": "Email already exists"}), 401

if __name__ == '__main__':
    app.run(debug=True)