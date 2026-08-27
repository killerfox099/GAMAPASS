import os
import csv
import io
import re
import smtplib
import random
import string
from email.mime.text import MIMEText
from flask import Flask, Response, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

app = Flask(__name__)

# ================= CONFIGURAÇÕES DINÂMICAS =================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave_de_sessao_fallback_local')

# Lê a URL do PostgreSQL da nuvem ou roda SQLite localmente se não configurado
db_url = os.environ.get('DATABASE_URL', 'sqlite:///banco_local.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Chave de criptografia Fernet (deve ter 32 bytes base64 url-safe)
chave_padrao = 'dCyX0U3oHIROiltcaOR1PwkWry4yhMSLmQve55uDtsA=' 
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', chave_padrao).strip().encode('utf-8')
cipher_suite = Fernet(ENCRYPTION_KEY)



# ================= MODELOS =================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    display_name = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(120), nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_first_login = db.Column(db.Boolean, default=True)
    requires_password_reset = db.Column(db.Boolean, default=False)
    
    machine_ip = db.Column(db.String(50), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    sector = db.Column(db.String(100), nullable=True)
    unit = db.Column(db.String(100), nullable=True)

class SavedPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_name = db.Column(db.String(100), nullable=False)
    service_url = db.Column(db.String(255), nullable=True)
    service_username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ================= FUNÇÃO DE E-MAIL (SKYMAIL) =================
def enviar_email_recuperacao(destinatario, nova_senha):
    remetente = os.environ.get('EMAIL_REMETENTE', "email_padrao@empresa.com.br")
    senha_email = os.environ.get('EMAIL_SENHA', "EMPTY_PASS")
    
    msg = MIMEText(f"Olá!\n\nSua senha do GAMAPASS foi redefinida.\nSua nova senha temporária é: {nova_senha}\n\nAo fazer login, o sistema exigirá o cadastro de uma nova senha segura.")
    msg['Subject'] = 'Recuperação de Acesso - GAMAPASS'
    msg['From'] = remetente
    msg['To'] = destinatario

    try:
        with smtplib.SMTP_SSL('smtp.skymail.net.br', 465) as server:
            server.login(remetente, senha_email)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Erro no envio SMTP: {e}")
        return False

# ================= ROTAS DE AUTENTICAÇÃO =================
@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            if user.requires_password_reset:
                return redirect(url_for('force_password_reset'))
            if user.is_first_login:
                return redirect(url_for('first_setup'))
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciais inválidas. Verifique usuário e senha.', 'error')
    return render_template('login.html')

@app.route('/esqueceu-senha', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        
        if user and user.email:
            temp_pass = ''.join(random.choices(string.ascii_lowercase, k=3)) + \
                        ''.join(random.choices(string.ascii_uppercase, k=3)) + \
                        ''.join(random.choices(string.digits, k=2)) + "@!"
            
            user.password_hash = generate_password_hash(temp_pass, method='scrypt')
            user.requires_password_reset = True
            db.session.commit()
            
            sucesso = enviar_email_recuperacao(user.email, temp_pass)
            if sucesso:
                flash('Uma senha temporária foi enviada para o e-mail cadastrado.', 'success')
            else:
                flash(f'Falha ao conectar com servidor de e-mail. Senha temporária: {temp_pass}', 'error')
                
            return redirect(url_for('login'))
        else:
            flash('Usuário não encontrado ou sem e-mail cadastrado.', 'error')
            
    return render_template('forgot_password.html')

@app.route('/primeiro-acesso', methods=['GET', 'POST'])
@login_required
def first_setup():
    if not current_user.is_first_login:
        return redirect(url_for('dashboard'))
        
    form_data = {}
    if request.method == 'POST':
        form_data = request.form
        new_password = request.form.get('new_password')
        
        regex_senha = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%*|&]).+$'
        if not re.match(regex_senha, new_password):
            flash('Erro: A senha não atende aos requisitos mínimos de segurança.', 'error')
            return render_template('first_setup.html', form_data=form_data)
        
        current_user.display_name = request.form.get('display_name')
        current_user.email = request.form.get('email')
        current_user.machine_ip = request.form.get('machine_ip')
        current_user.department = request.form.get('department')
        current_user.sector = request.form.get('sector')
        current_user.unit = request.form.get('unit')
        current_user.password_hash = generate_password_hash(new_password, method='scrypt')
        current_user.is_first_login = False
        
        db.session.commit()
        flash('Cadastro concluído com sucesso!', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('first_setup.html', form_data=form_data)

@app.route('/redefinir-senha', methods=['GET', 'POST'])
@login_required
def force_password_reset():
    if not current_user.requires_password_reset:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('As senhas não coincidem.', 'error')
            return render_template('reset_password.html')

        regex_senha = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%*|&]).+$'
        if not re.match(regex_senha, new_password):
            flash('A senha não atende aos requisitos de segurança.', 'error')
            return render_template('reset_password.html')

        current_user.password_hash = generate_password_hash(new_password, method='scrypt')
        current_user.requires_password_reset = False
        db.session.commit()

        flash('Sua senha foi atualizada com sucesso!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('reset_password.html')

# ================= PAINEL DO USUÁRIO & SENHAS =================
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.is_first_login:
        return redirect(url_for('first_setup'))

    if request.method == 'POST':
        service = request.form.get('service')
        service_url = request.form.get('service_url')
        service_user = request.form.get('service_user')
        service_pass = request.form.get('service_pass')
        
        # Bloqueio anti-duplicidade
        duplicado = SavedPassword.query.filter_by(
            user_id=current_user.id, 
            service_name=service, 
            service_username=service_user
        ).first()
        
        if duplicado:
            flash(f'Atenção: Já existe uma credencial salva para {service} com este usuário.', 'error')
            return redirect(url_for('dashboard'))

        encrypted_pw = cipher_suite.encrypt(service_pass.encode('utf-8'))
        new_entry = SavedPassword(
            user_id=current_user.id, 
            service_name=service, 
            service_url=service_url, 
            service_username=service_user, 
            encrypted_password=encrypted_pw
        )
        db.session.add(new_entry)
        db.session.commit()
        flash('Credencial salva com sucesso!', 'success')
        return redirect(url_for('dashboard'))

    saved_entries = SavedPassword.query.filter_by(user_id=current_user.id).all()
    decrypted_entries = []
    for entry in saved_entries:
        try:
            decrypted_pw = cipher_suite.decrypt(entry.encrypted_password).decode('utf-8')
        except Exception:
            decrypted_pw = "[Erro ao descriptografar]"
        decrypted_entries.append({
            'id': entry.id, 
            'service_name': entry.service_name, 
            'service_url': entry.service_url, 
            'service_username': entry.service_username, 
            'password': decrypted_pw
        })
        
    return render_template('dashboard.html', entries=decrypted_entries)

@app.route('/editar_senha/<int:pass_id>', methods=['POST'])
@login_required
def editar_senha(pass_id):
    entry = SavedPassword.query.get_or_404(pass_id)
    if entry.user_id != current_user.id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('dashboard'))

    entry.service_name = request.form.get('service', entry.service_name)
    entry.service_url = request.form.get('service_url', entry.service_url)
    entry.service_username = request.form.get('service_user', entry.service_username)
    
    nova_senha = request.form.get('service_pass')
    if nova_senha and nova_senha.strip() != '':
        entry.encrypted_password = cipher_suite.encrypt(nova_senha.encode('utf-8'))

    try:
        db.session.commit()
        flash('Credencial atualizada com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao atualizar: {e}', 'error')

    return redirect(url_for('dashboard'))

@app.route('/delete_password/<int:pass_id>', methods=['POST'])
@login_required
def delete_password(pass_id):
    entry = SavedPassword.query.get(pass_id)
    if entry and entry.user_id == current_user.id:
        db.session.delete(entry)
        db.session.commit()
        flash('Credencial apagada permanentemente.', 'success')
    return redirect(url_for('dashboard'))

# ================= IMPORTAÇÃO & EXPORTAÇÃO CSV =================
@app.route('/importar-csv', methods=['POST'])
@login_required
def importar_csv():
    if 'arquivo_csv' not in request.files:
        flash('Nenhum arquivo enviado.', 'error')
        return redirect(url_for('dashboard')) 
        
    arquivo = request.files['arquivo_csv']
    if arquivo.filename == '' or not arquivo.filename.endswith('.csv'):
        flash('Por favor, envie um arquivo .csv válido.', 'error')
        return redirect(url_for('dashboard'))
        
    try:
        conteudo = arquivo.stream.read().decode("utf-8-sig", errors="ignore")
        primeira_linha = conteudo.split('\n')[0]
        separador = ';' if primeira_linha.count(';') >= primeira_linha.count(',') else ','
            
        stream = io.StringIO(conteudo, newline=None)
        csv_input = csv.DictReader(stream, delimiter=separador)
        senhas_extraidas = []

        for row in csv_input:
            senha_limpa = ''
            usuario = ''
            url = ''
            dado_perdido = '' 
            
            for chave, valor in row.items():
                if not chave or not valor: 
                    continue
                k = str(chave).strip().lower()
                v = str(valor).strip()
                
                if 'senha' in k or 'password' in k or 'pass' in k:
                    senha_limpa = v
                elif 'usuário' in k or 'usuario' in k or 'user' in k or 'login' in k or 'email' in k or 'e-mail' in k:
                    usuario = v
                elif 'url' in k or 'link' in k:
                    url = v
                elif 'serviço' in k or 'servico' in k or 'name' in k or 'site' in k:
                    dado_perdido = v

            if not senha_limpa:
                continue

            if not usuario and dado_perdido:
                usuario = dado_perdido
            if not usuario:
                usuario = "N/A"

            senhas_extraidas.append({
                'usuario': usuario,
                'senha': senha_limpa,
                'url': url,
                'sugestao_servico': dado_perdido if not (not usuario and dado_perdido) else ''
            })

        if len(senhas_extraidas) == 0:
            flash('Nenhuma senha identificada no arquivo.', 'warning')
            return redirect(url_for('dashboard'))
            
        return render_template('revisar_importacao.html', senhas=senhas_extraidas)
        
    except Exception as e:
        flash(f'Erro ao ler arquivo: {e}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/salvar-importacao', methods=['POST'])
@login_required
def salvar_importacao():
    servicos = request.form.getlist('servicos[]')
    usuarios = request.form.getlist('usuarios[]')
    senhas = request.form.getlist('senhas[]')
    urls = request.form.getlist('urls[]')
    
    senhas_salvas = 0
    try:
        for i in range(len(servicos)):
            servico = servicos[i].strip()
            usuario = usuarios[i].strip()
            senha = senhas[i]
            url = urls[i].strip() if i < len(urls) else ''
            
            if not servico:
                continue
                
            duplicado = SavedPassword.query.filter_by(
                user_id=current_user.id, 
                service_name=servico, 
                service_username=usuario
            ).first()
            if duplicado:
                continue
                
            senha_criptografada = cipher_suite.encrypt(senha.encode('utf-8'))
            nova_senha = SavedPassword(
                user_id=current_user.id, 
                service_name=servico, 
                service_username=usuario, 
                encrypted_password=senha_criptografada, 
                service_url=url
            )
            db.session.add(nova_senha)
            senhas_salvas += 1
            
        db.session.commit()
        flash(f'{senhas_salvas} credenciais validadas e salvas com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao salvar senhas: {e}', 'error')
        
    return redirect(url_for('dashboard'))

@app.route('/exportar-csv')
@login_required
def exportar_csv():
    senhas = SavedPassword.query.filter_by(user_id=current_user.id).all()
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(['service_name', 'service_username', 'password', 'service_url'])

    for s in senhas:
        try:
            senha_limpa = cipher_suite.decrypt(s.encrypted_password).decode('utf-8')
        except Exception:
            senha_limpa = "[ERRO_CRIPTOGRAFIA]"
        writer.writerow([s.service_name, s.service_username, senha_limpa, s.service_url or ''])
        
    resposta = Response(output.getvalue().encode('utf-8-sig'), mimetype='text/csv')
    resposta.headers["Content-Disposition"] = "attachment; filename=gamapass_exportacao.csv"
    return resposta

# ================= PAINEL ADMINISTRATIVO =================
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'bulk_create':
            bulk_usernames = request.form.get('bulk_usernames')
            default_password = request.form.get('default_password')
            is_admin = request.form.get('is_admin') == 'on'
            
            if not bulk_usernames or not default_password:
                flash('Preencha os logins e a senha provisória.', 'error')
                return redirect(url_for('admin_panel'))
                
            usernames_list = [u.strip() for u in bulk_usernames.split(',') if u.strip()]
            adicionados = 0
            ignorados = 0
            
            for uname in usernames_list:
                existente = User.query.filter_by(username=uname).first()
                if existente:
                    ignorados += 1
                    continue
                    
                novo_usuario = User(
                    username=uname,
                    password_hash=generate_password_hash(default_password, method='scrypt'),
                    is_admin=is_admin,
                    is_first_login=True
                )
                db.session.add(novo_usuario)
                adicionados += 1
                
            try:
                db.session.commit()
                if adicionados > 0:
                    flash(f'{adicionados} usuário(s) criados com sucesso!', 'success')
                if ignorados > 0:
                    flash(f'{ignorados} usuário(s) ignorados pois já existiam.', 'warning')
            except Exception as e:
                db.session.rollback()
                flash(f'Erro interno: {e}', 'error')
                
            return redirect(url_for('admin_panel'))

    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/editar_usuario/<int:user_id>', methods=['POST'])
@login_required
def editar_usuario(user_id):
    if not current_user.is_admin:
        flash('Acesso negado.', 'error')
        return redirect(url_for('dashboard'))

    usuario = User.query.get_or_404(user_id)
    usuario.username = request.form.get('username', usuario.username)
    usuario.display_name = request.form.get('display_name', usuario.display_name)
    usuario.department = request.form.get('department', usuario.department)
    usuario.sector = request.form.get('sector', usuario.sector)
    usuario.unit = request.form.get('unit', usuario.unit)
    usuario.machine_ip = request.form.get('machine_ip', usuario.machine_ip)
    
    nova_senha = request.form.get('new_password')
    if nova_senha and nova_senha.strip() != '':
        usuario.password_hash = generate_password_hash(nova_senha, method='scrypt')
        usuario.requires_password_reset = True

    try:
        db.session.commit()
        flash(f'Usuário {usuario.username} atualizado com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao atualizar usuário: {e}', 'error')

    return redirect(url_for('admin_panel'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Acesso negado.', 'error')
        return redirect(url_for('admin_panel'))

    usuario = User.query.get_or_404(user_id)
    try:
        SavedPassword.query.filter_by(user_id=usuario.id).delete()
        db.session.delete(usuario)
        db.session.commit()
        flash(f'Usuário {usuario.username} e suas senhas foram excluídos.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir: {e}', 'error')

    return redirect(url_for('admin_panel'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ================= INICIALIZAÇÃO DO BANCO E ADMIN INICIAL =================
with app.app_context():
    try:
        db.create_all()
        # Se não houver nenhum usuário cadastrado no banco, cria o primeiro Admin
        if not User.query.first():
            admin_user = os.environ.get('INITIAL_ADMIN_USER', 'admin')
            admin_pass = os.environ.get('INITIAL_ADMIN_PASS', 'Admin@123456')
            admin_obj = User(
                username=admin_user,
                password_hash=generate_password_hash(admin_pass, method='scrypt'),
                is_admin=True,
                is_first_login=False,
                display_name="Administrador do Sistema"
            )
            db.session.add(admin_obj)
            db.session.commit()
            print(f"[INFO] Administrador inicial criado com sucesso: login='{admin_user}'")
    except Exception as e:
        print(f"[AVISO] Falha ao inicializar tabelas na inicialização: {e}")

if __name__ == '__main__':
    porta = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=porta)