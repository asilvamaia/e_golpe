import sys
import os
import json
from pathlib import Path

# Adiciona o diretório raiz ao sys.path para conseguir importar `database`
sys.path.append(str(Path(__file__).parent.parent))

from database.db import SessionLocal, init_db, PASTA_DADOS
from database.models import Usuario, DatasetItem, Feedback, DomainList, AmeacaCache

def migrate_data():
    # Cria o banco de dados e as tabelas
    init_db()
    db = SessionLocal()

    try:
        print("Iniciando migração de dados...")

        # 1. Usuários
        usuarios_file = PASTA_DADOS / "usuarios_cadastrados.json"
        if usuarios_file.exists():
            with open(usuarios_file, "r") as f:
                usuarios = json.load(f)
                for u in usuarios:
                    user_id = str(u)
                    if not db.query(Usuario).filter(Usuario.user_id == user_id).first():
                        db.add(Usuario(user_id=user_id))
            print(f"Migrados {len(usuarios)} usuários.")

        # 2. Feedbacks
        feedbacks_file = PASTA_DADOS / "feedbacks.json"
        if feedbacks_file.exists():
            with open(feedbacks_file, "r", encoding="utf-8") as f:
                feedbacks = json.load(f)
                count = 0
                for fb in feedbacks:
                    db.add(Feedback(
                        input_usuario=fb.get("input_usuario", ""),
                        output_ia=fb.get("output_ia", ""),
                        avaliacao=fb.get("avaliacao", "")
                    ))
                    count += 1
            print(f"Migrados {count} feedbacks.")

        # 3. Dataset (Histórico)
        dataset_file = PASTA_DADOS / "dataset_treino.json"
        if dataset_file.exists():
            with open(dataset_file, "r", encoding="utf-8") as f:
                dataset = json.load(f)
                count = 0
                for item in dataset:
                    db.add(DatasetItem(
                        dados_tecnicos=item.get("dados_tecnicos", {}),
                        analise_modelo=item.get("analise_modelo", ""),
                        metadados=item.get("metadados", {})
                    ))
                    count += 1
            print(f"Migrados {count} itens do dataset.")

        # 4. Whitelist
        whitelist_file = PASTA_DADOS / "whitelist.txt"
        inserted_domains = set()
        if whitelist_file.exists():
            with open(whitelist_file, "r", encoding="utf-8") as f:
                domain_count = 0
                for line in f:
                    domain = line.strip().lower()
                    if domain and domain not in inserted_domains:
                        db.add(DomainList(domain=domain, list_type="whitelist"))
                        inserted_domains.add(domain)
                        domain_count += 1
            print(f"Migrados {domain_count} domínios da whitelist.")

        # 5. Blacklist (otimizado para 20MB)
        blacklist_file = PASTA_DADOS / "blacklist.txt"
        if blacklist_file.exists():
            print("Migrando blacklist usando bulk inserts...")
            with open(blacklist_file, "r", encoding="utf-8", errors="ignore") as f:
                batch = []
                domain_count = 0
                for line in f:
                    domain = line.strip().lower()
                    if domain and domain not in inserted_domains:
                        batch.append({"domain": domain, "list_type": "blacklist"})
                        inserted_domains.add(domain)
                        domain_count += 1
                        if len(batch) >= 20000:
                            db.bulk_insert_mappings(DomainList, batch)
                            db.commit()
                            batch = []
                            print(f"Migrados {domain_count} domínios da blacklist...")
                if batch:
                    db.bulk_insert_mappings(DomainList, batch)
                    db.commit()
            print(f"Migração da blacklist concluída. Total: {domain_count} domínios.")

        # Commit os arquivos menores também
        db.commit()
        print("Migração finalizada com sucesso!")

    except Exception as e:
        db.rollback()
        print(f"Erro durante a migração: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    migrate_data()
