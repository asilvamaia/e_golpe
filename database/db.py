import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base

pasta_atual = Path(__file__).parent.parent
if os.path.exists("/data"):
    PASTA_DADOS = Path("/data")
else:
    PASTA_DADOS = pasta_atual

DB_PATH = PASTA_DADOS / "guardian.db"
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

# Check_same_thread=False is needed for SQLite when used in multithreaded apps like FastAPI/Streamlit
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
