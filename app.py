import os
import csv
import io
import re
import ssl
import smtplib
import random
import string
from datetime import datetime
from email.mime.text import MIMEText
from flask import Flask, Response, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

app = Flask(__name__)

# Filtro customizado Jinja2 para regex no template
@app.template_filter('regex_search')
def regex_search_filter(value, pattern):
    """Retorna True se o padrão regex for encontrado no valor."""
    return bool(re.search(pattern, str(value)))

# ================= CONFIGURAÇÕES DINÂMICAS =================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave_de_sessao_fallback_local')

# Lê a URL do PostgreSQL da nuvem ou roda SQLite localmente se não configurado
db_url = os.environ.get('DATABASE_URL', 'sqlite:///banco_local.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 280,
}

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
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_hr = db.Column(db.Boolean, default=False)
    is_first_login = db.Column(db.Boolean, default=True)
    requires_password_reset = db.Column(db.Boolean, default=False)
    
    machine_ip = db.Column(db.String(50), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    sector = db.Column(db.String(100), nullable=True)
    unit = db.Column(db.String(100), nullable=True)
    last_login_date = db.Column(db.String(20), nullable=True) # Data no formato YYYY-MM-DD

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    author = db.relationship('User', backref='announcements')

class SavedPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_name = db.Column(db.String(100), nullable=False)
    service_url = db.Column(db.String(255), nullable=True)
    service_username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PasswordHistory(db.Model):
    """Histórico de alterações de uma credencial salva."""
    id = db.Column(db.Integer, primary_key=True)
    saved_password_id = db.Column(db.Integer, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_name = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # 'criada', 'alterada', 'removida'
    changed_by = db.Column(db.String(100), nullable=True)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    """Log de auditoria global do sistema."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    username_at_time = db.Column(db.String(100), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(500), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ================= DETECÇÃO DE IP =================
def get_client_ip():
    """Captura o endereço IP de conexão do usuário."""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP').strip()
    else:
        ip = request.remote_addr or '127.0.0.1'
    return ip

def registrar_auditoria(action, details=None):
    """Registra um evento no log de auditoria do sistema."""
    try:
        from flask_login import current_user as cu
        uid = cu.id if cu.is_authenticated else None
        uname = cu.username if cu.is_authenticated else 'Sistema'
        ip = get_client_ip()
        log = AuditLog(
            user_id=uid,
            username_at_time=uname,
            action=action,
            details=details,
            ip_address=ip
        )
        db.session.add(log)
        db.session.commit()
    except Exception as ex:
        print(f"[AUDIT] Falha ao registrar log: {ex}", flush=True)
        try:
            db.session.rollback()
        except Exception:
            pass




import json
import urllib.request
import urllib.error

# ================= FUNÇÕES DE E-MAIL (HTTPS API + SMTP FALLBACK) =================
def enviar_via_resend(destinatario, assunto, corpo):
    api_key = os.environ.get('RESEND_API_KEY', '').strip()
    if not api_key:
        return False, "Sem chave Resend"
    
    remetente = os.environ.get('RESEND_FROM', 'GAMAPASS <onboarding@resend.dev>').strip()
    payload = {
        "from": remetente,
        "to": [destinatario],
        "subject": assunto,
        "text": corpo
    }
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode('utf-8'),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "GAMAPASS/1.0"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            res_body = response.read().decode('utf-8')
            print(f"[RESEND HTTPS SUCESSO] E-mail entregue para {destinatario}! Resposta: {res_body}", flush=True)
            return True, "Enviado com sucesso via Resend (HTTPS)"
    except urllib.error.HTTPError as he:
        err_msg = he.read().decode('utf-8', errors='ignore')
        print(f"[RESEND HTTP ERROR {he.code}]: {err_msg}", flush=True)
        try:
            err_json = json.loads(err_msg)
            if 'message' in err_json:
                return False, f"Resend ({he.code}): {err_json['message']}"
        except Exception:
            pass
        return False, f"Resend ({he.code}): {err_msg}"
    except Exception as ex:
        print(f"[RESEND EXCEPTION]: {ex}", flush=True)
        return False, str(ex)

def enviar_via_brevo(destinatario, assunto, corpo):
    api_key = os.environ.get('BREVO_API_KEY', '').strip()
    if not api_key:
        return False, "Sem chave Brevo"
        
    remetente = os.environ.get('EMAIL_REMETENTE', 'auxinformatica.gamacam@gmail.com').strip()
    payload = {
        "sender": {"name": "GAMAPASS", "email": remetente},
        "to": [{"email": destinatario}],
        "subject": assunto,
        "textContent": corpo
    }
    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=json.dumps(payload).encode('utf-8'),
        headers={
            "api-key": api_key,
            "Content-Type": "application/json",
            "User-Agent": "GAMAPASS/1.0"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            print(f"[BREVO HTTPS SUCESSO] E-mail entregue para {destinatario}!", flush=True)
            return True, "Enviado com sucesso via Brevo (HTTPS)"
    except urllib.error.HTTPError as he:
        err_msg = he.read().decode('utf-8', errors='ignore')
        print(f"[BREVO ERRO]: {err_msg}", flush=True)
        return False, f"Brevo API: {err_msg}"
    except Exception as ex:
        print(f"[BREVO EXCEPTION]: {ex}", flush=True)
        return False, str(ex)

def disparar_email_smtp(destinatario, msg):
    """Detecta automaticamente o provedor (Gmail, Skymail, Outlook) e tenta SMTP."""
    remetente = os.environ.get('EMAIL_REMETENTE', "email_padrao@empresa.com.br").strip()
    senha_email = os.environ.get('EMAIL_SENHA', "EMPTY_PASS").strip().replace(" ", "")

    if not senha_email or senha_email == "EMPTY_PASS" or remetente == "email_padrao@empresa.com.br":
        print("[SMTP AVISO] EMAIL_REMETENTE ou EMAIL_SENHA não configurados no Render.", flush=True)
        return False, "Credenciais de e-mail não configuradas no Render."

    contexto_ssl = ssl.create_default_context()
    contexto_ssl.check_hostname = False
    contexto_ssl.verify_mode = ssl.CERT_NONE

    is_gmail = "gmail.com" in remetente.lower()
    if is_gmail:
        smtp_host = "smtp.gmail.com"
    elif "outlook.com" in remetente.lower() or "hotmail.com" in remetente.lower():
        smtp_host = "smtp-mail.outlook.com"
    else:
        smtp_host = os.environ.get('SMTP_SERVER', "smtp.skymail.net.br").strip()

    erros = []

    # --- Tentativa 1: Porta 587 (STARTTLS) ---
    try:
        print(f"[SMTP] Tentando {smtp_host}:587 (STARTTLS)...", flush=True)
        with smtplib.SMTP(smtp_host, 587, timeout=6) as server:
            server.ehlo()
            server.starttls(context=contexto_ssl)
            server.ehlo()
            server.login(remetente, senha_email)
            server.send_message(msg)
        print(f"[SMTP 587 SUCESSO via {smtp_host}] E-mail entregue para {destinatario}!", flush=True)
        return True, f"Enviado com sucesso via {smtp_host}"
    except smtplib.SMTPAuthenticationError as auth_err:
        msg_auth = f"Erro de autenticação no {smtp_host}."
        if is_gmail:
            msg_auth += " No Gmail, use a Senha de App de 16 letras."
        return False, msg_auth
    except Exception as e587:
        erros.append(f"Porta 587: {e587}")

    # --- Tentativa 2: Porta 465 (SSL) ---
    try:
        print(f"[SMTP] Tentando {smtp_host}:465 (SSL)...", flush=True)
        with smtplib.SMTP_SSL(smtp_host, 465, context=contexto_ssl, timeout=6) as server:
            server.login(remetente, senha_email)
            server.send_message(msg)
        print(f"[SMTP 465 SUCESSO via {smtp_host}] E-mail entregue para {destinatario}!", flush=True)
        return True, f"Enviado com sucesso via {smtp_host}"
    except smtplib.SMTPAuthenticationError as auth_err:
        msg_auth = f"Erro de autenticação no {smtp_host}."
        if is_gmail:
            msg_auth += " No Gmail, use a Senha de App de 16 letras."
        return False, msg_auth
    except Exception as e465:
        erros.append(f"Porta 465: {e465}")

    erro_detalhe = " | ".join(erros)
    if "101" in erro_detalhe or "unreachable" in erro_detalhe.lower():
        erro_detalhe = "O Render bloqueia as portas SMTP 587/465 na camada gratuita. Para enviar e-mails, configure uma chave RESEND_API_KEY ou BREVO_API_KEY no Render."
    return False, erro_detalhe

def enviar_email_geral(destinatario, assunto, corpo):
    """Envia por API HTTPS (Resend/Brevo) se configurado, ou por SMTP como fallback."""
    resend_key = os.environ.get('RESEND_API_KEY', '').strip()
    if resend_key:
        sucesso, msg_resend = enviar_via_resend(destinatario, assunto, corpo)
        if sucesso:
            return True, msg_resend
        else:
            return False, f"Resend API: {msg_resend}"
            
    brevo_key = os.environ.get('BREVO_API_KEY', '').strip()
    if brevo_key:
        sucesso, msg_brevo = enviar_via_brevo(destinatario, assunto, corpo)
        if sucesso:
            return True, msg_brevo
        else:
            return False, f"Brevo API: {msg_brevo}"

    remetente = os.environ.get('EMAIL_REMETENTE', "email_padrao@empresa.com.br").strip()
    msg = MIMEText(corpo, 'plain', 'utf-8')
    msg['Subject'] = assunto
    msg['From'] = f"GAMAPASS - Gama Caminhões <{remetente}>"
    msg['To'] = destinatario
    msg['Reply-To'] = remetente

    return disparar_email_smtp(destinatario, msg)


def enviar_email_recuperacao(destinatario, nova_senha):
    assunto = 'Recuperação de Acesso - GAMAPASS'
    corpo = (
        f"Olá!\n\nSua senha do GAMAPASS foi redefinida.\n"
        f"Sua nova senha temporária é: {nova_senha}\n\n"
        f"Ao fazer login, o sistema exigirá o cadastro de uma nova senha segura."
    )
    sucesso, _ = enviar_email_geral(destinatario, assunto, corpo)
    return sucesso

def enviar_email_convite(destinatario, username, senha_provisoria, link_acesso):
    assunto = 'Convite de Acesso - GAMAPASS (Gama Caminhões)'
    corpo = (
        f"Olá!\n\n"
        f"Você foi cadastrado na plataforma GAMAPASS — o cofre corporativo de credenciais e senhas da Gama Caminhões.\n\n"
        f"Abaixo estão os seus dados para o primeiro acesso:\n"
        f"🔗 Link de Acesso: {link_acesso}\n"
        f"👤 Usuário: {username}\n"
        f"🔑 Senha Provisória: {senha_provisoria}\n\n"
        f"⚠️ Importante: Ao fazer login pela primeira vez, o sistema solicitará obrigatoriamente "
        f"que você cadastre sua senha pessoal definitiva e complete seus dados.\n\n"
        f"Atenciosamente,\n"
        f"Equipe de Tecnologia da Informação\n"
        f"Gama Caminhões"
    )
    return enviar_email_geral(destinatario, assunto, corpo)









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
            registrar_auditoria('LOGIN', f'Usuário {username} fez login com sucesso.')
            
            # Registra a data de acesso (mantém o IP interno da máquina intacto)
            hoje = datetime.now().strftime('%Y-%m-%d')
            if user.last_login_date != hoje:
                user.last_login_date = hoje
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            
            if user.requires_password_reset:
                return redirect(url_for('force_password_reset'))
            if user.is_first_login:
                return redirect(url_for('first_setup'))
            return redirect(url_for('dashboard'))
        else:
            registrar_auditoria('LOGIN_FALHA', f'Tentativa de login falhou para usuário: {username}.')
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
        
    form_data = {
        'display_name': current_user.display_name or '',
        'email': current_user.email or '',
        'machine_ip': current_user.machine_ip or ''
    }
    return render_template('first_setup.html', form_data=form_data)

@app.route('/atualizar_meu_ip', methods=['POST'])
@login_required
def atualizar_meu_ip():
    novo_ip = request.form.get('machine_ip', '').strip()
    if novo_ip:
        current_user.machine_ip = novo_ip
        try:
            db.session.commit()
            flash(f'IP da máquina atualizado com sucesso para: {novo_ip}', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao salvar IP: {e}', 'error')
    else:
        flash('Por favor, informe o endereço IP fixo da sua máquina.', 'warning')
        
    return redirect(url_for('dashboard'))


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
        db.session.flush()  # Para obter o ID gerado antes do commit

        # Registra no histórico da credencial
        hist = PasswordHistory(
            saved_password_id=new_entry.id,
            user_id=current_user.id,
            service_name=service,
            action='criada',
            changed_by=current_user.username
        )
        db.session.add(hist)
        db.session.commit()
        registrar_auditoria('SENHA_CRIADA', f'Credencial criada para o serviço "{service}" (usuário: {service_user}).')
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
        
    avisos = Announcement.query.order_by(Announcement.created_at.desc()).all()
        
    return render_template('dashboard.html', entries=decrypted_entries, avisos=avisos)

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
        # Registra no histórico
        hist = PasswordHistory(
            saved_password_id=entry.id,
            user_id=current_user.id,
            service_name=entry.service_name,
            action='alterada',
            changed_by=current_user.username
        )
        db.session.add(hist)
        db.session.commit()
        registrar_auditoria('SENHA_EDITADA', f'Credencial do serviço "{entry.service_name}" foi editada.')
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
        service_name = entry.service_name
        # Registra remoção no histórico antes de apagar
        hist = PasswordHistory(
            saved_password_id=entry.id,
            user_id=current_user.id,
            service_name=service_name,
            action='removida',
            changed_by=current_user.username
        )
        db.session.add(hist)
        db.session.delete(entry)
        db.session.commit()
        registrar_auditoria('SENHA_REMOVIDA', f'Credencial do serviço "{service_name}" foi removida.')
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
        
        # CADASTRO INDIVIDUAL COM CONVITE POR E-MAIL
        if action == 'create_single':
            username = request.form.get('username', '').strip()
            email_prefix = request.form.get('email_prefix', '').strip()
            password = request.form.get('password', '').strip()
            is_admin = request.form.get('is_admin') == 'on'
            is_hr = request.form.get('is_hr') == 'on'
            send_email = request.form.get('send_email') == 'on'
            
            if not username or not password:
                flash('Preencha o login e a senha provisória.', 'error')
                return redirect(url_for('admin_panel'))
                
            if User.query.filter_by(username=username).first():
                flash(f"Erro: O usuário '{username}' já existe no sistema.", 'error')
                return redirect(url_for('admin_panel'))
                
            full_email = None
            if email_prefix:
                clean_prefix = email_prefix.split('@')[0].strip()
                full_email = f"{clean_prefix}@gamacaminhoes.com.br"
                
            novo_usuario = User(
                username=username,
                email=full_email,
                password_hash=generate_password_hash(password, method='scrypt'),
                is_admin=is_admin,
                is_hr=is_hr,
                is_first_login=True
            )
            try:
                db.session.add(novo_usuario)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                flash(f"Erro ao salvar novo usuário no banco: {e}", 'error')
                return redirect(url_for('admin_panel'))
            
            if send_email and full_email:
                link_acesso = request.host_url.rstrip('/') + url_for('login')
                sucesso, detalhe_erro = enviar_email_convite(full_email, username, password, link_acesso)
                if sucesso:
                    flash(f"Funcionário '{username}' cadastrado com sucesso e convite entregue em {full_email}!", 'success')
                else:
                    flash(f"Funcionário '{username}' cadastrado com sucesso! Porém o envio do e-mail falhou ({detalhe_erro}). Você pode clicar em '✉️ Reenviar Convite' na lista abaixo para tentar novamente. Senha provisória: {password}", 'warning')
            else:
                flash(f"Funcionário '{username}' cadastrado com sucesso!", 'success')
            
            registrar_auditoria('USUARIO_CRIADO', f'Novo usuário "{username}" ({full_email or "sem email"}) cadastrado pelo admin.')
            return redirect(url_for('admin_panel'))
            
        # CADASTRO EM MASSA
        elif action == 'bulk_create':
            bulk_usernames = request.form.get('bulk_usernames')
            default_password = request.form.get('default_password')
            is_admin = request.form.get('is_admin') == 'on'
            send_email_bulk = request.form.get('send_email_bulk') == 'on'
            
            if not bulk_usernames or not default_password:
                flash('Preencha os logins e a senha provisória.', 'error')
                return redirect(url_for('admin_panel'))
                
            usernames_list = [u.strip() for u in bulk_usernames.split(',') if u.strip()]
            adicionados = 0
            ignorados = 0
            emails_enviados = 0
            link_acesso = request.host_url.rstrip('/') + url_for('login')
            
            for uname in usernames_list:
                existente = User.query.filter_by(username=uname).first()
                if existente:
                    ignorados += 1
                    continue
                    
                auto_email = f"{uname.split('@')[0].strip()}@gamacaminhoes.com.br"
                novo_usuario = User(
                    username=uname,
                    email=auto_email,
                    password_hash=generate_password_hash(default_password, method='scrypt'),
                    is_admin=is_admin,
                    is_first_login=True
                )
                db.session.add(novo_usuario)
                adicionados += 1
                
                if send_email_bulk:
                    sucesso, _ = enviar_email_convite(auto_email, uname, default_password, link_acesso)
                    if sucesso:
                        emails_enviados += 1
                
            try:
                db.session.commit()
                msg_sucesso = f"{adicionados} usuário(s) criados com sucesso!"
                if send_email_bulk:
                    msg_sucesso += f" ({emails_enviados} e-mails de convite disparados)."
                if adicionados > 0:
                    flash(msg_sucesso, 'success')
                if ignorados > 0:
                    flash(f"{ignorados} usuário(s) ignorados pois já existiam.", 'warning')
            except Exception as e:
                db.session.rollback()
                flash(f'Erro interno: {e}', 'error')
                
            return redirect(url_for('admin_panel'))

    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin.html', users=users)

@app.route('/admin/reenviar_convite/<int:user_id>', methods=['GET', 'POST'])
@login_required
def reenviar_convite(user_id):

    # Redireciona se acessado diretamente pelo navegador (GET)
    if request.method == 'GET':
        return redirect(url_for('admin_panel'))

    if not current_user.is_admin:
        flash('Acesso negado.', 'error')
        return redirect(url_for('dashboard'))
        
    try:
        usuario = User.query.get_or_404(user_id)
        if not usuario.email:
            flash(f"O usuário '{usuario.username}' não possui e-mail cadastrado.", 'error')
            return redirect(url_for('admin_panel'))
            
        provisional_pass = request.form.get('provisional_password', '').strip()
        if not provisional_pass:
            provisional_pass = ''.join(random.choices(string.ascii_letters + string.digits, k=8)) + '@!'
            
        usuario.password_hash = generate_password_hash(provisional_pass, method='scrypt')
        usuario.is_first_login = True
        db.session.commit()
        
        link_acesso = request.host_url.rstrip('/') + url_for('login')
        sucesso, detalhe_erro = enviar_email_convite(usuario.email, usuario.username, provisional_pass, link_acesso)
        if sucesso:
            flash(f"Convite reenviado com sucesso para {usuario.email}! Senha provisória: {provisional_pass}", 'success')
        else:
            flash(f"Falha ao enviar e-mail para {usuario.email} ({detalhe_erro}). Senha provisória gerada: {provisional_pass}", 'warning')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro inesperado ao reenviar convite: {str(e)}', 'error')
        
    return redirect(url_for('admin_panel'))




@app.route('/editar_usuario/<int:user_id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(user_id):
    if not current_user.is_admin:
        flash('Acesso negado.', 'error')
        return redirect(url_for('dashboard'))
        
    if request.method == 'GET':
        return redirect(url_for('admin_panel'))

    usuario = User.query.get_or_404(user_id)
    usuario.username = request.form.get('username', usuario.username)
    usuario.display_name = request.form.get('display_name', usuario.display_name)
    
    email_val = request.form.get('email', '').strip()
    if email_val:
        if '@' not in email_val:
            email_val = f"{email_val}@gamacaminhoes.com.br"
        usuario.email = email_val
    else:
        usuario.email = None
        
    usuario.department = request.form.get('department', usuario.department)
    usuario.sector = request.form.get('sector', usuario.sector)
    usuario.unit = request.form.get('unit', usuario.unit)
    usuario.machine_ip = request.form.get('machine_ip', usuario.machine_ip)
    
    # Checkbox forms enviam 'on' se marcado, None se desmarcado
    usuario.is_admin = request.form.get('is_admin') == 'on'
    usuario.is_hr = request.form.get('is_hr') == 'on'
    
    nova_senha = request.form.get('new_password')

    if nova_senha and nova_senha.strip() != '':
        usuario.password_hash = generate_password_hash(nova_senha, method='scrypt')
        usuario.requires_password_reset = True

    try:
        db.session.commit()
        registrar_auditoria('USUARIO_EDITADO', f'Dados do usuário "{usuario.username}" atualizados pelo admin.')
        flash(f'Usuário {usuario.username} atualizado com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao atualizar usuário: {e}', 'error')

    return redirect(url_for('admin_panel'))

@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Acesso negado.', 'error')
        return redirect(url_for('admin_panel'))
        
    if request.method == 'GET':
        return redirect(url_for('admin_panel'))

    usuario = User.query.get_or_404(user_id)
    nome_usuario = usuario.username
    try:
        SavedPassword.query.filter_by(user_id=usuario.id).delete()
        db.session.delete(usuario)
        db.session.commit()
        registrar_auditoria('USUARIO_REMOVIDO', f'Usuário "{nome_usuario}" e suas senhas foram excluídos pelo admin.')
        flash(f'Usuário {nome_usuario} e suas senhas foram excluídos.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir: {e}', 'error')

    return redirect(url_for('admin_panel'))


@app.route('/logout')
@login_required
def logout():
    registrar_auditoria('LOGOUT', f'Usuário {current_user.username} encerrou a sessão.')
    logout_user()
    return redirect(url_for('login'))

# ================= HISTÓRICO DE CREDENCIAL & AUDITORIA =================
@app.route('/historico_senha/<int:pass_id>')
@login_required
def historico_senha(pass_id):
    """Retorna o histórico de alterações de uma credencial em JSON."""
    entry = SavedPassword.query.get_or_404(pass_id)
    if entry.user_id != current_user.id and not current_user.is_admin:
        return {'error': 'Acesso negado'}, 403
    
    historico = PasswordHistory.query.filter_by(
        saved_password_id=pass_id
    ).order_by(PasswordHistory.changed_at.desc()).limit(20).all()
    
    resultado = []
    for h in historico:
        resultado.append({
            'acao': h.action,
            'por': h.changed_by or 'Desconhecido',
            'data': h.changed_at.strftime('%d/%m/%Y %H:%M') if h.changed_at else '-'
        })
    
    import json as _json
    from flask import Response as _Response
    return _Response(_json.dumps(resultado, ensure_ascii=False), mimetype='application/json')

@app.route('/admin/auditoria')
@login_required
def admin_auditoria():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    filtro_usuario = request.args.get('usuario', '').strip()
    filtro_acao = request.args.get('acao', '').strip()
    
    query = AuditLog.query
    if filtro_usuario:
        query = query.filter(AuditLog.username_at_time.ilike(f'%{filtro_usuario}%'))
    if filtro_acao:
        query = query.filter(AuditLog.action == filtro_acao)
    
    logs = query.order_by(AuditLog.created_at.desc()).limit(500).all()
    usuarios = db.session.query(AuditLog.username_at_time).distinct().all()
    acoes_distintas = db.session.query(AuditLog.action).distinct().all()
    
    return render_template('auditoria.html',
        logs=logs,
        filtro_usuario=filtro_usuario,
        filtro_acao=filtro_acao,
        usuarios=[u[0] for u in usuarios if u[0]],
        acoes=[a[0] for a in acoes_distintas if a[0]]
    )

@app.route('/admin/exportar_auditoria')
@login_required
def exportar_auditoria():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(['Data/Hora', 'Usuário', 'Ação', 'Detalhes', 'IP'])
    for log in logs:
        writer.writerow([
            log.created_at.strftime('%d/%m/%Y %H:%M:%S') if log.created_at else '',
            log.username_at_time or '',
            log.action or '',
            log.details or '',
            log.ip_address or ''
        ])
    
    resposta = Response(output.getvalue().encode('utf-8-sig'), mimetype='text/csv')
    resposta.headers["Content-Disposition"] = "attachment; filename=gamapass_auditoria.csv"
    return resposta

# ================= PAINEL DE RH E AVISOS =================
@app.route('/rh')
@login_required
def rh_panel():
    if not (current_user.is_admin or current_user.is_hr):
        flash('Acesso negado. Esta área é restrita ao RH ou Administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    avisos = Announcement.query.order_by(Announcement.created_at.desc()).all()
    return render_template('rh_panel.html', avisos=avisos)

@app.route('/rh/aviso/novo', methods=['POST'])
@login_required
def rh_novo_aviso():
    if not (current_user.is_admin or current_user.is_hr):
        return redirect(url_for('dashboard'))
    
    titulo = request.form.get('titulo')
    conteudo = request.form.get('conteudo')
    
    if titulo and conteudo:
        aviso = Announcement(title=titulo, content=conteudo, author_id=current_user.id)
        db.session.add(aviso)
        db.session.commit()
        registrar_auditoria('AVISO_CRIADO', f'O RH/Admin "{current_user.username}" publicou um novo aviso: "{titulo}".')
        flash('Aviso publicado com sucesso!', 'success')
    else:
        flash('Título e conteúdo são obrigatórios.', 'error')
        
    return redirect(url_for('rh_panel'))

@app.route('/rh/aviso/deletar/<int:aviso_id>', methods=['POST'])
@login_required
def rh_deletar_aviso(aviso_id):
    if not (current_user.is_admin or current_user.is_hr):
        return redirect(url_for('dashboard'))
    
    aviso = Announcement.query.get_or_404(aviso_id)
    titulo = aviso.title
    db.session.delete(aviso)
    db.session.commit()
    
    registrar_auditoria('AVISO_REMOVIDO', f'O RH/Admin "{current_user.username}" removeu o aviso: "{titulo}".')
    flash('Aviso removido com sucesso!', 'success')
    return redirect(url_for('rh_panel'))

# ================= INICIALIZAÇÃO DO BANCO E MIGRAÇÃO AUTOMÁTICA =================
def inicializar_banco():
    from sqlalchemy import text, inspect
    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            print(f"[AVISO] db.create_all: {e}")
            
        try:
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            user_table = 'user' if 'user' in tables else ('users' if 'users' in tables else None)
            
            if user_table:
                cols = [c['name'] for c in inspector.get_columns(user_table)]
                is_postgres = 'postgres' in db.engine.url.drivername or 'postgresql' in str(db.engine.url)
                table_ref = f'"{user_table}"' if is_postgres else user_table
                
                columns_to_ensure = [
                    ('display_name', 'VARCHAR(100)'),
                    ('email', 'VARCHAR(120)'),
                    ('requires_password_reset', 'BOOLEAN DEFAULT FALSE'),
                    ('machine_ip', 'VARCHAR(50)'),
                    ('department', 'VARCHAR(100)'),
                    ('sector', 'VARCHAR(100)'),
                    ('unit', 'VARCHAR(100)'),
                    ('last_login_date', 'VARCHAR(20)'),
                    ('is_hr', 'BOOLEAN DEFAULT FALSE')
                ]
                
                for col_name, col_type in columns_to_ensure:
                    if col_name not in cols:
                        try:
                            with db.engine.begin() as conn:
                                print(f"[MIGRATION] Adicionando coluna {col_name} na tabela {table_ref}...")
                                conn.execute(text(f"ALTER TABLE {table_ref} ADD COLUMN {col_name} {col_type}"))
                        except Exception as ex:
                            print(f"[MIGRATION EXCEPTION] Coluna {col_name}: {ex}")

            # Migração: coluna created_at em saved_password
            if 'saved_password' in tables:
                sp_cols = [c['name'] for c in inspector.get_columns('saved_password')]
                is_postgres = 'postgres' in db.engine.url.drivername or 'postgresql' in str(db.engine.url)
                sp_ref = '"saved_password"' if is_postgres else 'saved_password'
                if 'created_at' not in sp_cols:
                    try:
                        with db.engine.begin() as conn:
                            print("[MIGRATION] Adicionando coluna created_at em saved_password...")
                            conn.execute(text(f"ALTER TABLE {sp_ref} ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
                    except Exception as ex:
                        print(f"[MIGRATION EXCEPTION] saved_password.created_at: {ex}")

                            
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
            print(f"[AVISO] Falha ao verificar/migrar tabelas: {e}")

# ================= TRATAMENTO DE ERROS GLOBAL =================
@app.errorhandler(500)
def internal_server_error(e):
    db.session.rollback()
    print(f"[ERRO 500]: {e}")
    flash("Ocorreu uma instabilidade momentânea na conexão com o servidor. Por favor, tente novamente.", "error")
    return redirect(url_for('dashboard' if current_user.is_authenticated else 'login'))

@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for('dashboard' if current_user.is_authenticated else 'login'))

if __name__ == '__main__':
    porta = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=porta)