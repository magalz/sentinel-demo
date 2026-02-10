import os
from dotenv import load_dotenv

# 1. Força o carregamento do arquivo .env
# O override=True garante que ele releia o arquivo mesmo se já tiver algo na memória
load_dotenv(override=True)

# 2. Tenta pegar a chave
api_key = os.getenv("GOOGLE_API_KEY")

# 3. Verifica e mostra o resultado
print("-" * 30)
if api_key:
    # Mostra só os 5 primeiros caracteres por segurança
    print(f"✅ SUCESSO! Chave encontrada.")
    print(f"🔑 Início da chave: {api_key[:5]}...")
    print(f"📏 Tamanho da chave: {len(api_key)} caracteres")
else:
    print("❌ ERRO: Chave NÃO encontrada.")
    print("Dicas:")
    print("1. O arquivo .env está na MESMA pasta que este script?")
    print("2. O arquivo se chama '.env' e não '.env.txt'?")
    print("3. Você salvou o arquivo .env (Ctrl+S)?")
print("-" * 30)