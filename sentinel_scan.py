import json
import sys
import os
import glob
import requests
import boto3
from datetime import datetime

# --- CONFIGURAÇÃO ---
GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-2')
DYNAMODB_TABLE = 'SentinelMonitor' # Nome da sua tabela

# Conexão com DynamoDB (Usa as credenciais do ambiente automaticamente)
try:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    table = dynamodb.Table(DYNAMODB_TABLE)
except Exception as e:
    print(f"⚠️ Aviso: Não foi possível conectar ao DynamoDB: {e}")
    table = None

def save_to_dashboard(filename, status, risco, detalhe):
    """Salva o resultado do scan no DynamoDB para aparecer no Dashboard"""
    if not table: return

    try:
        # Cria um ID único para cada execução (timestamp + arquivo)
        run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
        
        item = {
            'id_recurso': f"PR-{run_id}-{filename}", # ID Único
            'data_evento': str(datetime.now()),
            'tipo': 'IAC', # Importante para filtrar no dashboard
            'status_ia': 'VULNERAVEL' if status == 'REPROVADO' else 'SEGURO',
            'risco': risco if risco else "Nenhum risco detectado",
            'detalhe': detalhe if detalhe else "Arquivo aprovado na análise estática.",
            'usuario': 'GitHub Actions CI/CD',
            'json_analise': json.dumps({'status': status, 'file': filename})
        }
        table.put_item(Item=item)
        print(f"💾 Resultado de '{filename}' salvo no Dashboard.")
    except Exception as e:
        print(f"❌ Erro ao salvar no banco: {e}")

def analyze_iac(file_path):
    print(f"\n🔍 Sentinel AI: Analisando '{file_path}'...")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            iac_data = json.load(f)
    except Exception as e:
        return {"status": "ERRO_LEITURA", "risco": f"Erro ao ler arquivo: {e}"}

    prompt = f"""
    Atue como Auditor DevSecOps. Analise este IaC.
    Riscos Críticos: SG 0.0.0.0/0 (SSH/RDP), S3 Público, IAM Admin (*).
    
    ARQUIVO: {json.dumps(iac_data, default=str)}

    Responda JSON:
    {{
        "status": "APROVADO" ou "REPROVADO",
        "risco": "Titulo curto",
        "detalhe": "Explicação curta",
        "correcao": "Sugestão"
    }}
    """
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GOOGLE_API_KEY}"
    headers = {"Content-Type": "application/json"}
    body = {"contents": [{"parts": [{"text": prompt}]}]}
    
    try:
        response = requests.post(url, headers=headers, json=body)
        if response.status_code != 200: return {"status": "ERRO_API"}
        
        text = response.json()['candidates'][0]['content']['parts'][0]['text']
        clean_text = text.replace("```json", "").replace("```", "").strip()
        return json.loads(clean_text)
    except:
        return {"status": "ERRO_GERAL"}

# --- MAIN ---
if __name__ == "__main__":
    files = glob.glob("*.json")
    files = [f for f in files if f not in ["package.json", "tsconfig.json"]]
    
    if not files: sys.exit(0)

    fails = 0
    
    for file_name in files:
        res = analyze_iac(file_name)
        status = res.get('status', 'ERRO')
        risco = res.get('risco')
        detalhe = res.get('detalhe')
        
        # Salva no Banco (Seja Verde ou Vermelho)
        save_to_dashboard(file_name, status, risco, detalhe)

        if status == 'REPROVADO':
            print(f"🚫 [FALHA] {file_name} - {risco}")
            fails += 1
        elif status == 'APROVADO':
            print(f"✅ [OK] {file_name}")
        else:
            print(f"⚠️ [ERRO] {file_name}")
            fails += 1

    if fails > 0: sys.exit(1)
    else: sys.exit(0)
