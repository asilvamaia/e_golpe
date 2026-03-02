from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()

class Usuario(Base):
    __tablename__ = 'usuarios'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class DatasetItem(Base):
    __tablename__ = 'dataset'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    dados_tecnicos = Column(JSON)
    analise_modelo = Column(Text)
    metadados = Column(JSON)

class Feedback(Base):
    __tablename__ = 'feedbacks'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    input_usuario = Column(Text)
    output_ia = Column(Text)
    avaliacao = Column(String)

class DomainList(Base):
    __tablename__ = 'domain_list'
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String, index=True, unique=True)
    list_type = Column(String) # 'whitelist' or 'blacklist'
    added_at = Column(DateTime, default=datetime.utcnow)

class AmeacaCache(Base):
    __tablename__ = 'ameaca_cache'
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String, index=True, unique=True)
    added_at = Column(DateTime, default=datetime.utcnow)
