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
DYNAMODB_TABLE = 'SentinelMonitor'

try:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    table = dynamodb.Table(DYNAMODB_TABLE)
except Exception as e:
    print(f"⚠️ Aviso: Não foi possível conectar ao DynamoDB: {e}")
    table = None

def save_to_dashboard(filename, status, risco, detalhe, correcao):
    """Salva o resultado do scan no DynamoDB para o Dashboard"""
    if not table: return

    try:
        run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
        
        item = {
            'id_recurso': f"PR-{run_id}-{filename}",
            'data_evento': str(datetime.now()),
            'tipo': 'IAC',
            'status_ia': 'VULNERAVEL' if status == 'REPROVADO' else 'SEGURO',
            'risco': risco if risco else "Nenhum risco detectado",
            'detalhe': detalhe if detalhe else "Arquivo aprovado na análise estática.",
            'auto_correcao': correcao if correcao else "Nenhuma ação necessária.", # Campo restaurado
            'usuario': 'GitHub Actions CI/CD',
            'json_analise': json.dumps({'status': status, 'file': filename})
        }
        table.put_item(Item=item)
        print(f"💾 Resultado de '{filename}' salvo no Dashboard.")
    except Exception as e:
        print(f"❌ Erro ao salvar no banco: {e}")

def analyze_iac(file_path):
    print(f"\n🔍 Sentinel AI: Auditoria Semântica em '{file_path}'...")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            iac_data = json.load(f)
    except Exception as e:
        return {"status": "ERRO_LEITURA", "risco": f"Erro ao ler arquivo: {e}"}

    # PROMPT AMPLIADO (Auditoria Geral de Segurança)
    prompt = f"""
    Atue como Auditor DevSecOps Sênior. Sua missão é realizar uma análise de segurança profunda neste arquivo de Infraestrutura como Código (IaC).
    Não se limite a regras fixas. Identifique qualquer configuração que viole os princípios do AWS Well-Architected Framework ou Benchmarks CIS.

    FOCO DA ANÁLISE:
    1. EXPOSIÇÃO: Portas administrativas ou de banco de dados abertas para o mundo.
    2. PRIVILÉGIO: Uso de "AdministratorAccess", "Action: *" ou falta de MFA.
    3. CRIPTOGRAFIA: Recursos de armazenamento (S3, EBS, RDS) sem criptografia ativa.
    4. GOVERNANÇA: Ausência de logs, monitoramento ou versionamento.
    5. SEGREDOS: Chaves de acesso ou senhas expostas no código.

    ARQUIVO: {json.dumps(iac_data, default=str)}

    Responda ESTRITAMENTE em formato JSON (sem markdown):
    {{
        "status": "APROVADO" ou "REPROVADO",
        "risco": "Título do risco (ex: RDS sem Criptografia)",
        "detalhe": "Explicação técnica de como isso afeta a segurança",
        "correcao": "O que o desenvolvedor deve mudar no código"
    }}
    """
    
    # Usando o modelo flash 2.0 que é mais rápido e inteligente para código
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GOOGLE_API_KEY}"
    headers = {"Content-Type": "application/json"}
    body = {"contents": [{"parts": [{"text": prompt}]}]}
    
    try:
        response = requests.post(url, headers=headers, json=body)
        if response.status_code != 200: 
            print(f"Erro API: {response.text}")
            return {"status": "ERRO_API"}
        
        text = response.json()['candidates'][0]['content']['parts'][0]['text']
        clean_text = text.replace("```json", "").replace("```", "").strip()
        return json.loads(clean_text)
    except Exception as e:
        print(f"Erro na análise: {e}")
        return {"status": "ERRO_GERAL"}

# --- MAIN ---
if __name__ == "__main__":
    files = glob.glob("*.json")
    # Ignora arquivos de configuração de ambiente do node/python
    files = [f for f in files if f not in ["package.json", "tsconfig.json", "package-lock.json"]]
    
    if not files:
        print("ℹ️ Nenhum arquivo IaC encontrado para análise.")
        sys.exit(0)

    fails = 0
    
    for file_name in files:
        res = analyze_iac(file_name)
        status = res.get('status', 'ERRO')
        risco = res.get('risco')
        detalhe = res.get('detalhe')
        correcao = res.get('correcao')
        
        save_to_dashboard(file_name, status, risco, detalhe, correcao)

        if status == 'REPROVADO':
            print(f"🚫 [FALHA] {file_name}")
            print(f"   Risco: {risco}")
            print(f"   Correção: {correcao}")
            fails += 1
        elif status == 'APROVADO':
            print(f"✅ [OK] {file_name}")
        else:
            print(f"⚠️ [ERRO] {file_name}")
            fails += 1

    if fails > 0:
        print(f"\n❌ Pipeline bloqueado: {fails} vulnerabilidade(s) encontrada(s).")
        sys.exit(1)
    else:
        print("\n🎉 Todos os arquivos aprovados pelo Sentinel AI!")
        sys.exit(0)
