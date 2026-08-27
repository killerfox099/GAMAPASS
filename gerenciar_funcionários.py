import sys
from app import app, db, User
from werkzeug.security import generate_password_hash

def adicionar_funcionario():
    print("=== Sistema de Gerenciamento do Cofre ===")
    
    # Trava de segurança solicitada
    senha_acesso = input("Digite a senha de autorização do administrador: ")
    if senha_acesso != "prbh3263":
        print("Erro: Senha de autorização incorreta. Acesso negado.")
        sys.exit() # Encerra o script imediatamente
        
    print("\n--- Acesso Liberado ---")
    username = input("Digite o nome de usuário (login): ")
    password = input("Digite a senha provisória: ")
    is_admin_input = input("Este usuário será um Administrador? (s/n): ")
    
    is_admin = True if is_admin_input.lower() == 's' else False

    with app.app_context():
        db.create_all()
        if User.query.filter_by(username=username).first():
            print("Erro: Este usuário já existe.")
            return

        hashed_password = generate_password_hash(password, method='scrypt')
        
        novo_usuario = User(
            username=username, 
            password_hash=hashed_password,
            is_admin=is_admin,
            is_first_login=True
        )
        db.session.add(novo_usuario)
        db.session.commit()
        
        tipo = "Administrador" if is_admin else "Funcionário padrão"
        print(f"Sucesso! {tipo} '{username}' cadastrado.")

if __name__ == '__main__':
    adicionar_funcionario()