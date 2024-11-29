from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
from sqlalchemy_serializer import SerializerMixin
from datetime import datetime

db = SQLAlchemy()

# Many-to-Many Association Tables
department_reports = db.Table(
    'departments_reports',
    db.Column('department_id', db.Integer, db.ForeignKey('departments.id'), primary_key=True),
    db.Column('report_id', db.Integer, db.ForeignKey('reports.id'), primary_key=True)
)

user_departments = db.Table(
    'users_departments',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('department_id', db.Integer, db.ForeignKey('departments.id'), primary_key=True)
)

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    

    # One-to-Many relationship with reports
    reports = db.relationship("Report", backref="user", cascade="all, delete-orphan")

    # Many-to-Many relationship with departments
    departments = db.relationship("Department", secondary=user_departments, back_populates="users")

    @validates('password')
    def validate_password(self, key, password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        return password

class Department(db.Model, SerializerMixin):
    __tablename__ = 'departments'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)

    # Many-to-Many relationship with reports
    reports = db.relationship("Report", secondary=department_reports, back_populates="departments")

    # Many-to-Many relationship with users
    users = db.relationship("User", secondary=user_departments, back_populates="departments")

class Report(db.Model, SerializerMixin):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    date_reported = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Many-to-Many relationship with departments
    departments = db.relationship("Department", secondary=department_reports, back_populates="reports")

class Collection(db.Model, SerializerMixin):
    __tablename__ = 'collections'
    id = db.Column(db.Integer, primary_key=True)
    type_of_collection = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
