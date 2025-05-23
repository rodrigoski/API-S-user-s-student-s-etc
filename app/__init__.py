from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from datetime import timedelta

# Inicializar extensiones
db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    
    # Configuración
    app.config.update({
        'SQLALCHEMY_DATABASE_URI': 'postgresql://rodrigoski:1234@localhost/wikitek_prod',
        'JWT_SECRET_KEY': 'clave_secreta_32bytes_1234567890ABCDEF',
        'JWT_ACCESS_TOKEN_EXPIRES': timedelta(hours=3),
        'SQLALCHEMY_TRACK_MODIFICATIONS': False
    })
    
    # CORS
    CORS(app,
         origins=["http://localhost:5173"],
         supports_credentials=True,
         allow_headers=["Authorization", "Content-Type"],
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    )
    
    # Inicializar extensiones con la app
    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    
    # Registrar blueprints
    from app.routes import auth_bp, students_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(students_bp, url_prefix='/students')
    
    return app