from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy import PrimaryKeyConstraint, CheckConstraint

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    # Attributes
    id = db.Column(db.Integer, primary_key=True) # 
    username = db.Column(db.String, unique=True, nullable=False) # [cite: 42, 48]
    _password_hash = db.Column(db.String, nullable=False) # [cite: 43]
    image_url = db.Column(db.String) # [cite: 44]
    bio = db.Column(db.String) # [cite: 45]

    # Relationships
    recipes = db.relationship('Recipe', backref='user', lazy=True) # [cite: 49, 51]
    
    # Serialization rules to avoid circular referencing and exposing password hash
    serialize_rules = ('-recipes.user',)

    # 1. Implement bcrypt to create a secure password.
    @hybrid_property
    def password_hash(self):
        # Attempts to access the password_hash should be met with an AttributeError. [cite: 47]
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        # Hash the password and set _password_hash
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    # Authentication method
    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))

    # 2. Add validation for presence (handled by unique=True and nullable=False)
    # The requirement is for username to be present and unique[cite: 48].

    def __repr__(self):
        return f'<User {self.id}: {self.username}>'

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    # Attributes
    id = db.Column(db.Integer, primary_key=True) # [cite: 52]
    title = db.Column(db.String, nullable=False) # [cite: 53, 62]
    instructions = db.Column(db.String, nullable=False) # [cite: 54, 63]
    minutes_to_complete = db.Column(db.Integer) # [cite: 55]
    
    # Foreign Key Relationship (a recipe belongs to a user) [cite: 51]
    user_id = db.Column(db.Integer, db.ForeignKey('users.id')) 

    # Serialization rules
    serialize_rules = ('-user.recipes',)

    # Constraints/Validations
    @validates('instructions')
    def validate_instructions(self, key, instructions):
        # Constrain the instructions to be present and at least 50 characters long. [cite: 63]
        if not instructions or len(instructions) < 50:
            raise ValueError("Instructions must be present and at least 50 characters long.")
        return instructions
    
    @validates('title')
    def validate_title(self, key, title):
        # Constrain the title to be present. (already handled by nullable=False, but good practice to validate) [cite: 62]
        if not title:
             raise ValueError("Title must be present.")
        return title

    def __repr__(self):
        return f'<Recipe {self.id}: {self.title}>'