from db import db
import peeweedbevolve # new; must be imported before models
from flask import Flask, render_template, request, jsonify
from models import User, Item
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_user, LoginManager, UserMixin, logout_user
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity
)
from flask_cors import CORS

app = Flask(__name__)

app.secret_key=b'6\x99\xbc\xddJe\xd1]B\x02V\x1b~_\x13^\xab\x86$\xad\r\x03\xc5\x0e'

login_manager = LoginManager()
login_manager.init_app(app)

jwt = JWTManager(app)

cors = CORS(app, resources={r"/*": {"origins": "*"}})

@app.before_request
def before_request():
    db.connect()

@app.after_request
def after_request(response):
    db.close()
    return response

@app.cli.command()
def migrate():
    db.evolve(ignore_tables={'base_model'}, interactive=False) 

@login_manager.user_loader
def load_user(user_id):
    return User.get(User.id == user_id)

@app.route("/signup", methods=["POST"])
def signup():
    name = request.json.get("name")
    email = request.json.get("email")
    password = request.json.get("password")
    valid_email = not User.select().where(User.email == email).exists()
    valid_password = len(password) <= 6
    hashed_password = generate_password_hash(password)
    if valid_email and valid_password:
        user = User(name= name, email= email,password=hashed_password)
        user.save()
        return jsonify({
            "access_token": create_access_token(identity=user.id),
            "message": "Successfully created a user.",
            "status": "success",
            "user": {
                "name": user.name,
                "email": user.email,
                "password": user.password
                }
            })
    else:
        return jsonify ({ "msg" : "fail" })


@app.route("/login", methods=['GET', 'POST'])
def login():
    email = request.json.get("email")
    password = request.json.get("password")
    user = User.get_or_none(User.email == email)
    if user and check_password_hash(user.password, password):
        login_user(user)
        return jsonify({
            "access_token": create_access_token(identity=user.id),
            "message": "Successfully created a user and signed in.",
            "status": "success",
            "user": {
                "email": user.email,
                "password": user.password
                }
            })
    else:
        return jsonify ({ "msg" : "email or password incorrect" })


@app.route("/userprofile")
@jwt_required
def userprofile():
    current_user_id = get_jwt_identity()
    user = User.get_or_none(User.id == current_user_id)
    return jsonify({
                    "user": {
                            "name": user.name,
                            "email": user.email,        
                            "id": user.id
                            }})

@app.route('/update', methods=['POST', 'GET'])
@jwt_required
def update():
    current_user_id = get_jwt_identity()
    user = User.get_by_id(current_user_id)
    email = request.json.get("email")
    name = request.json.get("name")
    password = request.json.get("password")
    valid_password = len(password) >= 6
    hashed_password = generate_password_hash(password)
    user.email = email
    user.name = name
    user.password = hashed_password
    if user.save():
        return jsonify({
            "message": "Successfully updated.",
            "status": "success",
            "user": {
                "name": user.name,
                "email": user.email,
                "password": user.password
                }
            })
    else:
        return jsonify ({ "msg" : "fail" })


@app.route('/delete_user', methods=['POST'])
@jwt_required
def delete_user():
    current_user_id = get_jwt_identity()
    user = User.get_by_id(current_user_id)
    logout_user()
    if user.delete_instance():
        return jsonify ({"msg": "success"})
    else:
        return jsonify ({"msg": "fail"})


@app.route("/create_item", methods=["POST"])
@jwt_required
def createitem():
    current_user_id = get_jwt_identity()
    user = User.get_by_id(current_user_id)
    name = request.json.get("name")
    valid_name=not Item.select().where(Item.name == name).exists()
    if valid_name:
        item = Item(name = name, user=user)
        item.save()
        return jsonify({
            "access_token": create_access_token(identity=user.id),
            "message": "Successfully created a item.",
            "status": "success",
            "item": {
                "name": item.name,
                "id": item.id,
                }
            })
    else:
        return jsonify ({ "msg" : "fail" })

@app.route("/itemlist")
@jwt_required
def itemlist():
    current_user_id = get_jwt_identity()
    user = User.get_by_id(current_user_id)
    if user:
        item = Item.get_or_none()
        return jsonify({
                        "item": {
                                "id": item.id,
                                "name": item.name
                                }})




if __name__ == '__main__':
    app.run()
