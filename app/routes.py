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
from datetime import timedelta

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Blueprints
auth_bp = Blueprint('auth_bp', __name__)
students_bp = Blueprint('students_bp', __name__)

def handle_error(message, status_code):
    logger.error(message)
    return jsonify({"error": message}), status_code

# ==================== AUTENTICACIÓN ====================
@auth_bp.route('/login', methods=['POST'])
@cross_origin(supports_credentials=True)
def login():
    try:
        data = request.get_json()
        if not data:
            return handle_error("Datos inválidos", 400)

        email = str(data.get('email', '')).lower().strip()
        password = str(data.get('password', '')).strip()

        if not email or not password:
            return handle_error("Credenciales requeridas", 400)

        user = User.query.filter_by(email=email).first()
        
        if not user:
            return handle_error("Usuario no encontrado", 404)
        
        # Verificar contraseña
        if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            return handle_error("Contraseña incorrecta", 401)

        # Generar token JWT
        access_token = create_access_token(
            identity=user.id,
            expires_delta=timedelta(hours=3)
        )

        return jsonify({
            "access_token": access_token,
            "user_info": {
                "id": user.id,
                "email": user.email
            }
        }), 200

    except Exception as e:
        logger.error(f"Error en login: {str(e)}", exc_info=True)
        return handle_error("Error interno del servidor", 500)

@auth_bp.route('/register', methods=['POST'])
@cross_origin(supports_credentials=True)
def register():
    try:
        data = request.get_json()
        email = str(data.get('email', '')).lower().strip()
        password = str(data.get('password', '')).strip()

        if not email or not password:
            return handle_error("Email y contraseña requeridos", 400)

        if User.query.filter_by(email=email).first():
            return handle_error("Email ya registrado", 409)

        # Generar hash seguro
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        new_user = User(email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Usuario creado exitosamente"}), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error en registro: {str(e)}", exc_info=True)
        return handle_error("Error en registro", 500)

# ==================== ESTUDIANTES ====================
@students_bp.route('/', methods=['GET'])
def get_students():
    try:
        # Obtener todos los estudiantes de la base de datos
        students = Student.query.all()
        
        # Serializar los resultados
        students_list = []
        for student in students:
            students_list.append({
                'id': student.id,
                'user_id': student.user_id,
                'full_name': student.full_name,
                'email': student.email,
                'semester': student.semester,
                'skills': student.skills.split(',') if student.skills else [],
                'created_at': student.created_at.isoformat(),
                'updated_at': student.updated_at.isoformat()
            })
        
        return jsonify(students_list), 200
    
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({
            'error': 'Database error',
            'message': str(e)
        }), 500
    
    except Exception as e:
        return jsonify({
            'error': 'Server error',
            'message': str(e)
        }), 500