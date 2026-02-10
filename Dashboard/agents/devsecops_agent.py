import os
import json
import google.generativeai as genai

def analyze_code(code_content):
    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
    model = genai.GenerativeModel('gemini-2.5-flash')

    prompt = f"""
    Atue como um Engenheiro de DevSecOps.
    Analise o código Python abaixo em busca de vulnerabilidades (OWASP, senhas expostas, etc).

    Retorne APENAS um JSON válido (sem markdown) com este formato exato:
    {{
        "vulnerabilidades": [
            {{
                "tipo": "Nome do erro",
                "linha": "Trecho/Linha",
                "severidade": "ALTA/MEDIA/BAIXA",
                "detalhe": "Explicação do risco"
            }}
        ],
        "codigo_seguro": "Código completo corrigido e seguro"
    }}

    Código: {code_content}
    """
    try:
        response = model.generate_content(prompt)
        clean_text = response.text.replace("```json", "").replace("```", "").strip()
        return json.loads(clean_text)
    except Exception as e:
        return {"error": True, "message": str(e)}