import json
import sys
import os
import glob
import requests

# --- CONFIGURAÇÃO ---
GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')

def analyze_iac(file_path):
    print(f"\n🔍 Sentinel AI: Analisando '{file_path}'...")
    
    try:
        with open(file_path, 'r') as f:
            iac_data = json.load(f)
    except Exception as e:
        print(f"⚠️ Pulo: Não foi possível ler '{file_path}' ({e})")
        return {"status": "ERRO_LEITURA"}

    # Prompt Otimizado para IaC
    prompt = f"""
    Atue como Auditor DevSecOps. Analise este arquivo de Infraestrutura (Terraform/CloudFormation/JSON).
    
    Identifique riscos CRÍTICOS que impediriam o deploy:
    1. Security Groups com 'cidr_blocks': ['0.0.0.0/0'] em portas 22 (SSH) ou 3389 (RDP).
    2. Buckets S3 com 'acl': 'public-read' ou policies abertas para o mundo.
    3. IAM Roles com 'Action': '*' e 'Resource': '*' (Admin total).

    ARQUIVO IAC: {json.dumps(iac_data, default=str)}

    Responda APENAS neste JSON:
    {{
        "status": "APROVADO" ou "REPROVADO",
        "risco": "Titulo curto (ou null se seguro)",
        "detalhe": "Explicação curta",
        "correcao": "O que mudar no código"
    }}
    """
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GOOGLE_API_KEY}"
    headers = {"Content-Type": "application/json"}
    body = {"contents": [{"parts": [{"text": prompt}]}]}
    
    try:
        response = requests.post(url, headers=headers, json=body)
        if response.status_code != 200:
            print(f"❌ Erro API Gemini: {response.text}")
            return {"status": "ERRO_API"}
            
        result = response.json()
        text_resp = result['candidates'][0]['content']['parts'][0]['text']
        text_resp = text_resp.replace("```json", "").replace("```", "").strip()
        
        return json.loads(text_resp)

    except Exception as e:
        print(f"❌ Falha na análise: {e}")
        return {"status": "ERRO_GERAL"}

# --- LOOP DE EXECUÇÃO PRINCIPAL ---
if __name__ == "__main__":
    # Busca todos os arquivos .json na pasta atual
    files_to_scan = glob.glob("*.json")
    
    if not files_to_scan:
        print("⚠️ Nenhum arquivo .json encontrado para análise.")
        sys.exit(0)

    print(f"📂 Arquivos encontrados: {len(files_to_scan)}")
    
    erros_encontrados = 0
    
    for file_name in files_to_scan:
        # Pula arquivos de sistema ou configs do próprio projeto se houver
        if file_name in ["package.json", "tsconfig.json"]: 
            continue
            
        resultado = analyze_iac(file_name)
        
        if resultado.get('status') == 'REPROVADO':
            print(f"❌ [FALHA] {file_name}")
            print(f"   Risco: {resultado.get('risco')}")
            print(f"   Correção: {resultado.get('correcao')}")
            erros_encontrados += 1
        elif resultado.get('status') == 'APROVADO':
            print(f"✅ [OK] {file_name} - Seguro.")
        else:
            print(f"⚠️ [SKIP] {file_name} - {resultado.get('status')}")

    print("\n" + "="*40)
    if erros_encontrados > 0:
        print(f"🚫 BLOCK: {erros_encontrados} arquivo(s) vulnerável(is) detectado(s).")
        sys.exit(1) # Quebra o Pipeline
    else:
        print("✅ SUCESSO: Todos os arquivos estão seguros.")
        sys.exit(0) # Passa o Pipeline