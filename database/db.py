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
# If DATABASE_URL is set in the environment (e.g. Railway PostgreSQL), use it.
# Otherwise, default to the local SQLite file.
db_url_env = os.environ.get("DATABASE_URL")

if db_url_env:
    # Some platforms (like Railway) provide 'postgres://' which SQLAlchemy 1.4+ no longer accepts
    if db_url_env.startswith("postgres://"):
        db_url_env = db_url_env.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URL = db_url_env
else:
    SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

# Check_same_thread=False is needed for SQLite when used in multithreaded apps like FastAPI/Streamlit
connect_args = {}
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args=connect_args
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

# Auto-inicializa o banco ao importar o módulo
init_db()
