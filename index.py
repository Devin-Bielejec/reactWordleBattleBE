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

@app.route("/createGame", methods=["POST"])
def createGame():
    email1 = request.json.get("email1")
    email2 = request.json.get("email2")
    word = request.json.get("word")
    if not (email1 and email2 and word):
        return jsonify({"message": "Need word and both emails"}), 401
    
    #Mongo will create and inserted_id which is unique
    #Word2 is for email2
    db.games.insert_one({"email1": email1, "email2": email2, "word2": word, "word1": "", completedDate: ""})

    return jsonify({"message": "Game Created!"}), 200

@app.route("/getGames", methods=["GET"])
def getGames():
    #Get only open games
    email = request.json.get("email")

    games = db.games.find({completedDate: ""})

    return jsonify({games}), 200

@app.route("/acceptGame", methods=["POST"])
def acceptGame():
    email = request.json.get("email")
    word = request.json.get("word")
    #GameID would have come from getGames and user clicked on game etc
    gameID = request.json.get("gameID")

    if not (email and word and gameID):
        return jsonify({"message": "Need word, gameID, and email please"}), 401
    
    #Update game by gameID
    db.games.update_one({
        {"inserted_id":gameID},
        {"word1": word}
    })

    return jsonify({"message": "Game Accepted"}), 200

#Try to find the email of a user to start a game with them
@app.route("/getEmail", methods=["POST"])
def getEmail():
    email = request.json.get("email")

    emails = db.users.find({"email": email})
    if not emails:
        return jsonify({"message": "No user with that Email"}), 401
    return jsonify({"message": "Email Found!"}), 200

def submitGuess():
    #Check if both players have either gotten the word or ran out of guesses, then set completedDate of the game to the current date
    return True

@app.route("/verifyWord", methods=["POST"])
def verifyWord():
    word = request.json.get("word")
    
    res = requests.get("https://api.dictionaryapi.dev/api/v2/entries/en/" + word)
    response = json.loads(res.text)
    print(response)
    if res:
        return jsonify({"message": "It's a word!", "data": response})
    return jsonify({"message": "It is not a word!"})

if __name__ == '__main__':
    app.run(debug=True)