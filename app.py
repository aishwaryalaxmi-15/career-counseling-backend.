from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///career_counseling.db'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this to a secure key in production

db = SQLAlchemy(app)
jwt = JWTManager(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"msg": "Username already exists"}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"msg": "Email already exists"}), 400

    user = User(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        access_token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(days=1))
        return jsonify(access_token=access_token)
    return jsonify({"msg": "Invalid username or password"}), 401

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    return jsonify(username=user.username, email=user.email)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
# Add this below the User model in app.py

class Career(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    skills_required = db.Column(db.Text)
    average_salary = db.Column(db.String(50))

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    career_id = db.Column(db.Integer, db.ForeignKey('career.id'), nullable=False)
    url = db.Column(db.String(250))

    career = db.relationship('Career', backref=db.backref('courses', lazy=True))

# API routes for Career and Course

@app.route('/careers', methods=['POST'])
@jwt_required()
def add_career():
    data = request.get_json()
    career = Career(
        name=data['name'],
        description=data['description'],
        skills_required=data.get('skills_required', ''),
        average_salary=data.get('average_salary', '')
    )
    db.session.add(career)
    db.session.commit()
    return jsonify({"msg": "Career added", "career_id": career.id}), 201

@app.route('/careers', methods=['GET'])
def get_careers():
    careers = Career.query.all()
    result = []
    for c in careers:
        result.append({
            "id": c.id,
            "name": c.name,
            "description": c.description,
            "skills_required": c.skills_required,
            "average_salary": c.average_salary
        })
    return jsonify(result)

@app.route('/courses', methods=['POST'])
@jwt_required()
def add_course():
    data = request.get_json()
    career = Career.query.get(data['career_id'])
    if not career:
        return jsonify({"msg": "Career not found"}), 404

    course = Course(
        title=data['title'],
        description=data['description'],
        career_id=data['career_id'],
        url=data.get('url', '')
    )
    db.session.add(course)
    db.session.commit()
    return jsonify({"msg": "Course added", "course_id": course.id}), 201

@app.route('/courses/<int:career_id>', methods=['GET'])
def get_courses_by_career(career_id):
    courses = Course.query.filter_by(career_id=career_id).all()
    result = []
    for c in courses:
        result.append({
            "id": c.id,
            "title": c.title,
            "description": c.description,
            "url": c.url
        })
    return jsonify(result)
