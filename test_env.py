import os
import boto3
import requests
from dotenv import load_dotenv

load_dotenv()

def test_aws():
    print("--- Testando AWS ---")
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        print(f"✅ Conectado como: {identity['Arn']}")
        
        dynamodb = boto3.resource('dynamodb', region_name=os.getenv('AWS_REGION', 'us-east-2'))
        table = dynamodb.Table('SentinelMonitor')
        # Tenta descrever a tabela para ver se existe e tem acesso
        table.table_status
        print(f"✅ Tabela 'SentinelMonitor' acessível.")
    except Exception as e:
        print(f"❌ Erro AWS: {e}")

def test_gemini():
    print("\n--- Testando Gemini API ---")
    api_key = os.getenv('GOOGLE_API_KEY')
    if not api_key or "sua_chave" in api_key:
        print("❌ GOOGLE_API_KEY não configurada no .env")
        return

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
    payload = {"contents": [{"parts": [{"text": "Reponda apenas 'OK'"}]}]}
    try:
        res = requests.post(url, json=payload)
        if res.status_code == 200:
            print("✅ Gemini API funcional.")
        else:
            print(f"❌ Erro Gemini: {res.status_code} - {res.text}")
    except Exception as e:
        print(f"❌ Erro de conexão Gemini: {e}")

if __name__ == "__main__":
    test_aws()
    test_gemini()
