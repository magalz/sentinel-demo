import json
import sys
import os
import requests

# --- CONFIGURAÇÃO ---
# Pegamos a API Key do ambiente (nunca chumbe no código!)
GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')

def analyze_iac(file_path):
    print(f"🔍 Sentinel AI: Analisando arquivo '{file_path}'...")
    
    try:
        with open(file_path, 'r') as f:
            iac_data = json.load(f)
    except Exception as e:
        print(f"❌ Erro ao ler arquivo: {e}")
        sys.exit(1)

    # O Prompt é o mesmo do Lambda, focado em IaC
    prompt = f"""
    Atue como Auditor DevSecOps. Analise este arquivo de Infraestrutura (Terraform/CloudFormation).
    
    Identifique riscos CRÍTICOS que impediriam o deploy:
    1. Security Groups com 'cidr_blocks': ['0.0.0.0/0'] em portas 22/3389.
    2. Buckets S3 com 'acl': 'public-read' ou policies abertas.
    3. IAM Roles com 'Action': '*' e 'Resource': '*'.

    ARQUIVO IAC (JSON): {json.dumps(iac_data, default=str)}

    Responda APENAS neste JSON:
    {{
        "status": "APROVADO" ou "REPROVADO",
        "risco": "Titulo curto",
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
            sys.exit(1)
            
        result = response.json()
        text_resp = result['candidates'][0]['content']['parts'][0]['text']
        # Limpa markdown se houver
        text_resp = text_resp.replace("```json", "").replace("```", "").strip()
        
        analysis = json.loads(text_resp)
        return analysis

    except Exception as e:
        print(f"❌ Falha na análise: {e}")
        sys.exit(1)

# --- EXECUÇÃO ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python sentinel_scan.py <arquivo_iac.json>")
        sys.exit(1)
    
    file_to_scan = sys.argv[1]
    resultado = analyze_iac(file_to_scan)
    
    print("\n" + "="*40)
    print(f"RELATÓRIO DE SEGURANÇA IA")
    print("="*40)
    print(f"STATUS: {resultado['status']}")
    print(f"RISCO:  {resultado.get('risco', 'Nenhum')}")
    print(f"DETALHE: {resultado.get('detalhe', '---')}")
    
    if resultado['status'] == 'REPROVADO':
        print("\n❌ BLOQUEIO DE PIPELINE ATIVADO!")
        print(f"💡 CORREÇÃO: {resultado.get('correcao')}")
        sys.exit(1) # Código de erro que quebra o GitHub Actions
    else:
        print("\n✅ CÓDIGO SEGURO. DEPLOY AUTORIZADO.")
        sys.exit(0) # Sucesso