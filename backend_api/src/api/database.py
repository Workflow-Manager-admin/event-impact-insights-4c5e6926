"""
Configures the SQLAlchemy database engine and session for the backend API.
Reads PostgreSQL connection settings from environment variables for flexibility across environments.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, scoped_session
from dotenv import load_dotenv

# PUBLIC_INTERFACE
def get_database_url():
    """
    Construct the database URL from environment variables for SQLAlchemy connection.
    """
    load_dotenv()
    user = os.getenv("POSTGRES_USER")
    password = os.getenv("POSTGRES_PASSWORD")
    host = os.getenv("POSTGRES_URL")
    port = os.getenv("POSTGRES_PORT")
    db = os.getenv("POSTGRES_DB")

    return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{db}"

DATABASE_URL = get_database_url()

# Base class for models, used throughout the ORM
Base = declarative_base()

# Create the SQLAlchemy engine
engine = create_engine(DATABASE_URL, echo=False, future=True)

# Session factory (thread-local)
SessionLocal = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=False))

# PUBLIC_INTERFACE
def get_db():
    """
    Yields a database session for FastAPI dependency injection.
    Cleans up after use.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
