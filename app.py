#Author: Original template from miguelgrinberg 
# repo:  https://github.com/miguelgrinberg/REST-auth
# Description: serves react app 
import os
import time
from flask_cors import CORS, cross_origin
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from flask_httpauth import HTTPBasicAuth
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

from config import SECRET_KEY, SQLALCHEMY_DATABASE_URI, SQLALCHEMY_COMMIT_ON_TEARDOWN
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = SQLALCHEMY_COMMIT_ON_TEARDOWN

db=SQLAlchemy(app)
auth= HTTPBasicAuth()
# cross origin 
# cors = CORS(app, resources={r"/api/*": {"origins": "*"}}, support_credentials=True)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['CORS_ORIGINS'] = ["http://localhost:3000"]




# model for users one to many with posts
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True, nullable=False)
    password_hash = db.Column(db.String(128))
    # post_id = db.Column(db.Integer,db.ForeignKey('posts.id'), nullable=False)
    posts = db.relationship('Posts',backref='users')
    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode(
            {'id': self.id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                              algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])

#model for posts many to one with user
class Posts(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    linkName = db.Column(db.String(32))
    url = db.Column()
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # user = db.relationship("User",backref="posts")

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users', methods=['POST','OPTIONS'])
@cross_origin(origins=['http://localhost:3000'])
def new_user():
    if request.method == 'OPTIONS':
        return 200
    
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201, 
            {'Location': url_for('get_user', id=user.id, _external=True)})

@app.route('/api/users/post', methods=['POST','OPTIONS'])
@auth.login_required
@cross_origin(origins=['http://localhost:3000'])
def newPost():
    if request.method == 'OPTIONS':
        return 200
    url = request.json.get('URL')
    linkName= request.json.get('linkName')
    if url is None or linkName is None:
        abort(400)
    user = g.user.id
    post = Posts(user_id=user)
    post.linkName=linkName
    post.url=url
    db.session.add(post)
    db.session.commit()
    return 200

    
    
    
      

@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/token', methods=['OPTIONS','GET'])
@cross_origin(origins=['http://localhost:3000'])
@auth.login_required
def get_auth_token():
    if request.method== 'OPTIONS':
        return 200
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token, 'duration': 600})


@app.route('/api/resource',methods=['OPTIONS','GET'])
@cross_origin(origins=['http://localhost:3000'])
@auth.login_required
def get_resource():
    if request.method == 'OPTIONS':
        return 200
    else: 
        return jsonify({'data': 'Hello, %s!' % g.user.username})

if not os.path.exists('db.sqlite'):
        db.create_all()
        db.session.commit()

# db.session.add(User(Posts()))

if __name__ == '__main__': 
    app.run(debug=True)
    