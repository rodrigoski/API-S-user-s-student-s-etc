from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity
)
from flask_cors import cross_origin
from app import db
from app.models import User, Student
import bcrypt
import logging

# Definir blueprints
auth_bp = Blueprint('auth_bp', __name__)
students_bp = Blueprint('students_bp', __name__)

def handle_error(message, status_code):
    logging.error(message)
    return jsonify({"error": message}), status_code

# ==================== AUTENTICACIÓN ====================
@auth_bp.route('/login', methods=['POST'])
@cross_origin(supports_credentials=True)
def login():
    try:
        data = request.get_json()
        email = str(data.get('email', '')).lower().strip()
        password = str(data.get('password', '')).strip()

        user = User.query.filter_by(email=email).first()
        
        if not user or not bcrypt.checkpw(password.encode(), user.password.encode()):
            return handle_error("Credenciales inválidas", 401)
            
        return jsonify({
            "access_token": create_access_token(identity=user.id),  # Solo el ID
        "user_info": {
            "id": user.id,
            "email": user.email
        }
    }), 200

    except Exception as e:
        logging.error(f"ERROR LOGIN: {str(e)}")
        return handle_error("Error interno del servidor", 500)

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
@cross_origin(supports_credentials=True)
def get_current_user():
    try:
        # Obtener identidad directamente del token
        user_id = get_jwt_identity()
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404
            
        return jsonify({
            "id": user.id,
            "email": user.email
        }), 200
        
    except Exception as e:
        logging.error(f"Error en /me: {str(e)}")
        return jsonify({"error": "Error de autenticación"}), 401

@auth_bp.route('/register', methods=['POST'])
@cross_origin(supports_credentials=True)
def register():
    try:
        data = request.get_json()
        email = str(data.get('email', '')).lower().strip()
        password = str(data.get('password', '')).strip()

        if User.query.filter_by(email=email).first():
            return handle_error("Email ya registrado", 409)

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        new_user = User(email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Usuario creado exitosamente"}), 201

    except Exception as e:
        db.session.rollback()
        return handle_error(f"Error en registro: {str(e)}", 500)

# ==================== ESTUDIANTES ====================
@students_bp.route('', methods=['GET'])
@jwt_required()
@cross_origin(supports_credentials=True)
def get_students():
    try:
        user_id = get_jwt_identity()  # Obtener ID directamente
        students = Student.query.filter_by(user_id=user_id).all()
        
        return jsonify([{
            "id": s.id,
            "full_name": s.full_name,
            "email": s.email,
            "semester": s.semester,
            "skills": s.skills.split(',') if s.skills else []
        } for s in students]), 200
        
    except Exception as e:
        logging.error(f"Error en /students: {str(e)}")
        return jsonify({"error": "Error al obtener estudiantes"}), 500
