import secrets
from cryptography.fernet import Fernet

def gerar_chaves():
    secret_key = secrets.token_hex(32)
    encryption_key = Fernet.generate_key().decode('utf-8')
    
    print("=" * 60)
    print("CHAVES DE SEGURANÇA GERADAS PARA O GAMAPASS (PRODUÇÃO)")
    print("=" * 60)
    print("\nCopie e cole essas variáveis no painel do seu servidor (Render):\n")
    print(f"SECRET_KEY={secret_key}")
    print(f"ENCRYPTION_KEY={encryption_key}")
    print("\n" + "=" * 60)
    print("ATENÇÃO: Guarde a ENCRYPTION_KEY em um local seguro!")
    print("Se você alterar ou perder a ENCRYPTION_KEY, as senhas salvas")
    print("no banco de dados não poderão mais ser descriptografadas.")
    print("=" * 60)

if __name__ == '__main__':
    gerar_chaves()
