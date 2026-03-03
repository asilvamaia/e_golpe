import json
import os
from pathlib import Path
from datetime import datetime
import sys

# Adiciona a raiz do projeto no path para encontrar o módulo database
ROOT_DIR = Path(__file__).parent.parent
sys.path.append(str(ROOT_DIR))

from database.db import SessionLocal
from database.models import Feedback

def gerar_dataset_finetuning():
    db = SessionLocal()
    try:
        # Busca feedbacks validos (onde o usuário discordou "NEGATIVO" ou aprovou enfaticamente "POSITIVO")
        feedbacks = db.query(Feedback).order_by(Feedback.timestamp.desc()).all()
        
        if not feedbacks:
            print("Nenhum feedback encontrado no banco de dados.")
            return

        exemplos = []
        for fb in feedbacks:
            # Estrutura JSONL esperada pelo Google Gemini Tuning
            # {"contents": [{"role": "user", "parts": [{"text": "input"}]}, {"role": "model", "parts": [{"text": "output corrigido"}]}]}
            
            # Aqui estamos assumindo que, no futuro, você pode ter uma tela que edita a resposta (output_ia) 
            # antes de enviar ao treinamento. Por enquanto, extraímos como estão.
            texto_usuario = fb.input_usuario or ""
            resposta_ia = fb.output_ia or ""
            
            # Ignora coisas vazias
            if len(texto_usuario) < 5 or not resposta_ia:
                continue

            exemplo = {
                "contents": [
                    {
                        "role": "user",
                        "parts": [{"text": f"Analise o seguinte conteúdo para segurança: {texto_usuario}"}]
                    },
                    {
                        "role": "model",
                        "parts": [{"text": resposta_ia}]
                    }
                ]
            }
            exemplos.append(exemplo)

        # Salva em um arquivo JSONL
        data_atual = datetime.now().strftime("%Y-%m-%d_%H%M")
        arquivo_saida = ROOT_DIR / f"dataset_retreino_{data_atual}.jsonl"
        
        with open(arquivo_saida, "w", encoding="utf-8") as f:
            for item in exemplos:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
                
        print(f"✅ Sucesso! {len(exemplos)} exemplos salvos em: {arquivo_saida.name}")
        print("Faça o download desse arquivo e importe no Google Vertex AI/AI Studio.")
        
    except Exception as e:
        print(f"Erro ao gerar dataset: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    print("Iniciando extração de Feedbacks do Banco de Dados...")
    gerar_dataset_finetuning()
