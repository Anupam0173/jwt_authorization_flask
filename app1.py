# flask imports
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
from werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)

# app.config['SECRET_KEY'] = 'your secret key'
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "your secret key")

# database name
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# creates SQLALCHEMY object
db = SQLAlchemy(app)

class User(db.Model):
    role = db.Column(db.String(50))
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique = True)
    password = db.Column(db.String(80))

# decorator for verifying the JWT
def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None
		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']
		if not token:
			return jsonify({'message' : 'Token is missing !!'}), 401

		try:
			data = jwt.decode(token, app.config['SECRET_KEY'])
			current_user = User.query\
				.filter_by(public_id = data['public_id'])\
				.first()
		except:
			return jsonify({
				'message' : 'Token is invalid !!'
			}), 401
		return f(current_user, *args, **kwargs)

	return decorated


@app.route('/student',methods=['POST'])
@token_required
def student(current_user):
    data = request.form
    entered_role = data.get('role')
    if entered_role == 'student':
        return jsonify({'response':"this is the route only for the student role."})
    return jsonify({'response':"you don't have student role."})

@app.route('/admin', methods =['post'])
@token_required
def admin(current_user):
    data = request.form
    entered_role = data.get('role')
    if entered_role == 'admin':
        users = User.query.all()
        output = []
        for user in users:
            output.append({
                'public_id': user.public_id,
                'name' : user.name,
                'email' : user.email
            })
        return jsonify({'users': output})
    return jsonify({'response':"you don't have admin role."})
    

# route for logging user in
@app.route('/login', methods =['POST'])
def login():
	# creates dictionary of form data
	auth = request.form

	if not auth or not auth.get('email') or not auth.get('password'):
		# returns 401 if any email or / and password is missing
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
		)

	user = User.query\
		.filter_by(email = auth.get('email'))\
		.first()

	if not user:
		# returns 401 if user does not exist
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
		)

	if check_password_hash(user.password, auth.get('password')):
		# generates the JWT Token
		token = jwt.encode({
			'public_id': user.public_id,
			'exp' : datetime.utcnow() + timedelta(minutes = 30)
		}, app.config['SECRET_KEY'])

		return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
	# returns 403 if password is wrong
	return make_response(
		'Could not verify',
		403,
		{'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
	)

# signup route
@app.route('/signup', methods =['POST'])
def signup():
	# creates a dictionary of the form data
	data = request.form
	name, email = data.get('name'), data.get('email')
	password, role = data.get('password'), data.get('role')

	# checking for existing user
	user = User.query.filter_by(email = email).first()
	if not user:
		user = User(
			public_id = str(uuid.uuid4()),
			name = name,
			email = email,
			password = generate_password_hash(password),
            role = role
		)
		db.session.add(user)
		db.session.commit()
		return make_response('Successfully registered.', 201)
	else:
		return make_response('User already exists. Please Log in.', 202)



if __name__ == "__main__":
	app.run(debug = True)
