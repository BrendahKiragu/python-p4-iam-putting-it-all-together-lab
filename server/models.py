from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    #relationship: a user has many recipes
    recipes = db.relationship('Recipe', backref='user')

    
    @validates('username')
    def validate_username(self, key, username):
        if User.query.filter_by(username=username).first() is not None:
            raise ValueError("Username already taken!")
        return username
    
    @hybrid_property
    def password_hash(self):
        raise AttributeError("password hashes may not br viewed.")
    
    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))

        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    #relationship: a recipe belongs to a user
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    @validates('instructions')
    def validate_instructions(self, key, instruction):
        if len(instruction) < 50:
            raise ValueError("Instructions have to be at least 50 characters long.")
        return instruction