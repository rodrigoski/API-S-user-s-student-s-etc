import os

class Config:
    SQLALCHEMY_DATABASE_URI = 'postgresql://rodrigoski:1234@localhost:5432/wikitek_prod'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "clave-secreta-para-desarrollo")