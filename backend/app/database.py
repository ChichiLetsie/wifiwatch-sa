from sqlalchemy import create_engine # connects raw connection bewteen python and database
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import SQLITE_DB_PATH

# SQLite-specific connect args for thread safety in multi-threaded environments
engine = create_engine(
    SQLITE_DB_PATH,
    connect_args={"check_same_thread": False},
    echo=False
)

#to open and close temporary work sessions whenever code needs to read or write data.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base() #define database tables as Python classes.

#gives each incoming web request its own database session and guarantees that session closes when the request is done.
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


