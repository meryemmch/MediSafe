import enum
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime,Enum
from sqlalchemy.orm import relationship
from backend.database import Base
from datetime import datetime

class UserRole(enum.Enum):
    radiologist = "radiologist"
    doctor = "doctor"
    patient = "patient"

class User(Base):
    __tablename__ = "users"
    user_id = Column(String, primary_key=True)  # UUID
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    hashed_aes_key = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    role = Column(Enum(UserRole), nullable=False)
    public_key = Column(String, nullable=False)  # PEM format


class EncryptedImage(Base):
    __tablename__ = 'images'

    image_id = Column(Integer, primary_key=True, index=True)
    encrypted_filename = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    encrypted_aes_key = Column(String, nullable=False)
    doctor_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    patient_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    doctor = relationship("User", foreign_keys=[doctor_id])
    patient = relationship("User", foreign_keys=[patient_id])


class Report(Base):
    __tablename__ = "reports"
    report_id = Column(String, primary_key=True)
    doctor_id = Column(String, ForeignKey("users.user_id"), nullable=False)
    patient_id = Column(String, ForeignKey("users.user_id"), nullable=False)
    encrypted_filename = Column(String, nullable=False)
    encrypted_aes_key = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    iv= Column(String, nullable=False)
    doctor = relationship("User", foreign_keys=[doctor_id])
    patient = relationship("User", foreign_keys=[patient_id])


