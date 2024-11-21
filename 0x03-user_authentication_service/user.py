"""User SQLAlchemy model
"""
from sqlalchemy.orm import declarative_base, decl_base
from sqlalchemy import Column, Integer, String

Base = declarative_base()


class User(Base):
    """User Model Definition
    """
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250))
    reset_token = Column(String(250))
