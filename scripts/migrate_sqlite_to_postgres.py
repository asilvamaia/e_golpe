import os
import io
import csv
import sqlite3
import psycopg2
from datetime import datetime

SQLITE_PATH = "guardian.db"
PG_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://60d4a7692fa440479c2e50398b01f6e7:20d117ecb606fb826d068a2b855dcf864941335e324963fdea337c9d483ccb7c@postgres.shardatabases.app:5432/egolpe?sslmode=require"
)

def migrate():
    print(f"Conectando ao SQLite: {SQLITE_PATH}...")
    s_conn = sqlite3.connect(SQLITE_PATH)
    s_cur = s_conn.cursor()

    print("Conectando ao PostgreSQL na ShardCloud...")
    pg_conn = psycopg2.connect(PG_URL)
    pg_cur = pg_conn.cursor()

    # 1. Feedbacks
    print("\n--- Migrando feedbacks ---")
    s_cur.execute("SELECT id, timestamp, input_usuario, output_ia, avaliacao FROM feedbacks")
    feedbacks = s_cur.fetchall()
    print(f"Total feedbacks a migrar: {len(feedbacks)}")
    for fb in feedbacks:
        pg_cur.execute("""
            INSERT INTO feedbacks (id, timestamp, input_usuario, output_ia, avaliacao)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING
        """, fb)
    pg_conn.commit()
    print("Feedbacks migrados com sucesso!")

    # 2. Dataset
    print("\n--- Migrando dataset ---")
    s_cur.execute("SELECT id, timestamp, dados_tecnicos, analise_modelo, metadados FROM dataset")
    dataset_rows = s_cur.fetchall()
    print(f"Total dataset a migrar: {len(dataset_rows)}")
    for ds in dataset_rows:
        pg_cur.execute("""
            INSERT INTO dataset (id, timestamp, dados_tecnicos, analise_modelo, metadados)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING
        """, ds)
    pg_conn.commit()
    print("Dataset migrado com sucesso!")

    # 3. DomainList (715k rows) usando streaming com COPY
    print("\n--- Migrando domain_list (otimizado via COPY) ---")
    pg_cur.execute("SELECT count(*) FROM domain_list;")
    current_count = pg_cur.fetchone()[0]
    print(f"Registros atuais em domain_list no Postgres: {current_count}")
    if current_count < 1000:
        s_cur.execute("SELECT id, domain, list_type, added_at FROM domain_list")
        
        batch_size = 50000
        total_migrated = 0
        while True:
            rows = s_cur.fetchmany(batch_size)
            if not rows:
                break
            
            buf = io.StringIO()
            writer = csv.writer(buf, delimiter='\t', quoting=csv.QUOTE_MINIMAL)
            for r in rows:
                # Trata campos nulos ou vazios
                row_list = [r[0], r[1] if r[1] else '', r[2] if r[2] else '', r[3] if r[3] else datetime.utcnow().isoformat()]
                writer.writerow(row_list)
            
            buf.seek(0)
            pg_cur.copy_from(buf, 'domain_list', columns=('id', 'domain', 'list_type', 'added_at'))
            pg_conn.commit()
            total_migrated += len(rows)
            print(f"Migrados {total_migrated} domínios...")
        print(f"Migração de domain_list concluída! Total: {total_migrated}")
    else:
        print("domain_list já possui registros no Postgres, pulando.")

    # 4. AmeacaCache (714k rows) usando streaming com COPY
    print("\n--- Migrando ameaca_cache (otimizado via COPY) ---")
    pg_cur.execute("SELECT count(*) FROM ameaca_cache;")
    current_count = pg_cur.fetchone()[0]
    print(f"Registros atuais em ameaca_cache no Postgres: {current_count}")
    if current_count < 1000:
        s_cur.execute("SELECT id, url, added_at FROM ameaca_cache")
        
        batch_size = 50000
        total_migrated = 0
        while True:
            rows = s_cur.fetchmany(batch_size)
            if not rows:
                break
            
            buf = io.StringIO()
            writer = csv.writer(buf, delimiter='\t', quoting=csv.QUOTE_MINIMAL)
            for r in rows:
                row_list = [r[0], r[1] if r[1] else '', r[2] if r[2] else datetime.utcnow().isoformat()]
                writer.writerow(row_list)
            
            buf.seek(0)
            pg_cur.copy_from(buf, 'ameaca_cache', columns=('id', 'url', 'added_at'))
            pg_conn.commit()
            total_migrated += len(rows)
            print(f"Migrados {total_migrated} caches de ameaça...")
        print(f"Migração de ameaca_cache concluída! Total: {total_migrated}")
    else:
        print("ameaca_cache já possui registros no Postgres, pulando.")

    # Atualizar sequências das chaves primárias
    for table in ['feedbacks', 'dataset', 'domain_list', 'ameaca_cache']:
        pg_cur.execute(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), coalesce(max(id), 1)) FROM {table};")
    pg_conn.commit()

    print("\n✅ Toda a base SQLite foi migrada com sucesso para o PostgreSQL na ShardCloud!")
    s_conn.close()
    pg_conn.close()

if __name__ == "__main__":
    migrate()
