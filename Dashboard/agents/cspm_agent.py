import json
import os
import time
import re  # Novo import para limpeza de texto
import google.generativeai as genai

def analyze_infra(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        return [{"error": f"Erro ao ler arquivo: {str(e)}"}]

    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
    model = genai.GenerativeModel('gemini-2.5-flash')

    results = []
    for resource in data.get('resources', []):
        prompt = f"""
        Atue como um especialista em Cloud Security (CSPM).
        Analise o recurso JSON abaixo e identifique riscos de segurança.
        
        Recurso: {json.dumps(resource)}

        Retorne APENAS um JSON válido com este formato exato:
        {{
            "resource_id": "{resource.get('id', 'unknown')}",
            "risco": "Nome curto do risco",
            "gravidade": "CRITICA, ALTA, MEDIA ou BAIXA",
            "descricao": "Explicação técnica curta",
            "correcao_cli": "Comando CLI para corrigir"
        }}
        """
        try:
            response = model.generate_content(prompt)
            raw_text = response.text
            
            # --- FILTRO ANTI-ERRO (REGEX) ---
            # Busca o primeiro '{' e o último '}' para ignorar textos extras da IA
            match = re.search(r'\{.*\}', raw_text, re.DOTALL)
            if match:
                clean_json = match.group(0)
                results.append(json.loads(clean_json))
            else:
                raise ValueError("IA não retornou um JSON válido")
            
            time.sleep(2) 
        except Exception as e:
            results.append({
                "resource_id": resource.get('id', 'unknown'),
                "risco": "Falha na Resposta",
                "gravidade": "ERRO",
                "descricao": f"Erro de processamento: {str(e)}",
                "correcao_cli": "N/A"
            })
    return results