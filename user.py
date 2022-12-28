from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, make_response
import uuid

from config import db, public_key, private_key


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(500))


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, public_key, algorithms=["RS256"])

            current_user = User.query\
                .filter_by(public_id=data['public_id'])\
                .first()
        except Exception as ex:
            print(ex)
            return jsonify({
                'message': 'Token is invalid!'
            }), 401

        return f(current_user, *args, **kwargs)
    return decorated


def get_token(credentials):

    if not credentials or not credentials.get('name') or not credentials.get('password'):
        return make_response('Parameters missing', 401)

    user = User.query.filter_by(name=credentials.get('name')).first()

    if not user:
        return make_response('User not existing', 401)

    if check_password_hash(user.password, credentials.get('password')):

        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, private_key, algorithm='RS256')

        return token, 201

    return make_response('Password is incorrect', 401)


@token_required
def get_all_users():
    users = User.query.all()

    output = []
    for user in users:
        output.append({
            'public_id': user.public_id,
            'name': user.name,
        })

    return jsonify({'users': output})


@token_required
def post_user(credentials):
    name = credentials.get('name')
    password = credentials.get('password')
    user = User.query.filter_by(name=name).first()
    if not user:
        user = User(
            public_id=str(uuid.uuid4()),
            name=name,
            password=generate_password_hash(password)
        )

    else:
        user.name = name
        user.password = generate_password_hash(password)
    # one or none

    db.session.add(user)
    db.session.commit()
    return


@token_required
def delete_user(id):
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    return make_response('Successfully deleted', 204)