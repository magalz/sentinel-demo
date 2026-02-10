import json
import sys
import os
import glob
import requests

# --- CONFIGURAÇÃO ---
GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')

def analyze_iac(file_path):
    print(f"\n🔍 Sentinel AI: Analisando '{file_path}'...")
    
    # 1. Tenta ler o arquivo JSON
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            iac_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ [ERRO SINTAXE] O arquivo '{file_path}' não é um JSON válido.")
        print(f"   Detalhe: {e}")
        return {"status": "ERRO_LEITURA", "risco": "JSON Malformado (Syntax Error)"}
    except Exception as e:
        print(f"❌ [ERRO LEITURA] Falha ao abrir arquivo: {e}")
        return {"status": "ERRO_LEITURA", "risco": "Arquivo Corrompido"}

    # 2. Prompt Otimizado
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
            return {"status": "ERRO_API", "risco": "Falha na Verificação IA"}
            
        result = response.json()
        text_resp = result['candidates'][0]['content']['parts'][0]['text']
        text_resp = text_resp.replace("```json", "").replace("```", "").strip()
        
        return json.loads(text_resp)

    except Exception as e:
        print(f"❌ Falha na análise: {e}")
        return {"status": "ERRO_GERAL", "risco": "Erro Interno do Scanner"}

# --- LOOP PRINCIPAL ---
if __name__ == "__main__":
    # Procura todos os JSONs na pasta
    files_to_scan = glob.glob("*.json")
    
    # Filtra arquivos de configuração do próprio projeto (se houver)
    files_to_scan = [f for f in files_to_scan if f not in ["package.json", "tsconfig.json"]]

    if not files_to_scan:
        print("⚠️ Nenhum arquivo de infraestrutura (.json) encontrado.")
        sys.exit(0)

    print(f"📂 Arquivos encontrados: {len(files_to_scan)}")
    
    arquivos_com_problema = 0
    
    for file_name in files_to_scan:
        resultado = analyze_iac(file_name)
        status = resultado.get('status')
        
        # LÓGICA DE BLOQUEIO RIGOROSA
        if status == 'REPROVADO':
            print(f"🚫 [VULNERÁVEL] {file_name}")
            print(f"   Risco: {resultado.get('risco')}")
            print(f"   Correção: {resultado.get('correcao')}")
            arquivos_com_problema += 1
            
        elif status in ['ERRO_LEITURA', 'ERRO_API', 'ERRO_GERAL']:
            print(f"🚫 [ERRO CRÍTICO] {file_name}")
            print(f"   Motivo: {resultado.get('risco')}")
            print("   Ação: Corrija o arquivo antes do deploy.")
            arquivos_com_problema += 1
            
        elif status == 'APROVADO':
            print(f"✅ [SEGURO] {file_name}")
        
        else:
            print(f"⚠️ [DESCONHECIDO] {file_name} - Status inválido da IA.")
            arquivos_com_problema += 1

    print("\n" + "="*40)
    if arquivos_com_problema > 0:
        print(f"❌ BLOQUEIO: {arquivos_com_problema} arquivo(s) impedem o deploy.")
        sys.exit(1) # Código de Erro (Quebra o GitHub Actions)
    else:
        print("✅ SUCESSO: Todos os arquivos estão válidos e seguros.")
        sys.exit(0) # Sucesso
