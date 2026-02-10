import os
import subprocess

def login_sistema(usuario, senha):
    # VULNERABILIDADE 1: Credenciais Hardcoded
    senha_admin = "123456" 
    
    if senha == senha_admin:
        print("Acesso concedido!")
        return True
    else:
        print("Acesso negado!")
        return False

def executar_manutencao():
    # VULNERABILIDADE 2: Command Injection
    ip = input("Digite o IP para pingar: ")
    # Perigoso: usuário pode digitar "8.8.8.8; rm -rf /"
    os.system("ping -c 1 " + ip)

if __name__ == "__main__":
    print("--- Sistema Sentinel Legacy ---")
    login_sistema("admin", "123456")