from datetime import datetime
from app import db
import bcrypt

class BaseModel(db.Model):
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class User(BaseModel):
    __tablename__ = 'users'
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(80), nullable=True)
    
    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=14)).decode()
        
    def check_password(self, password):
        return bcrypt.checkpw(password.encode(), self.password.encode())

class Student(BaseModel):
    __tablename__ = 'students'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True)
    semester = db.Column(db.Integer)
    skills = db.Column(db.String(255))