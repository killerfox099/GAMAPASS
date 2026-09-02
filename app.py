import os
import csv
import io
import re
import ssl
import smtplib
import random
import string
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from flask import Flask, Response, render_template, redirect, url_for, request, flash, send_file
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

from datetime import datetime, timedelta, timezone

BRT = timezone(timedelta(hours=-3))

def get_br_time():
    return datetime.now(BRT).replace(tzinfo=None)

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
    last_announcement_view = db.Column(db.DateTime, nullable=True)
    
    # Bloqueio por tentativas e auditoria de dispositivo
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(50), nullable=True)
    last_user_agent = db.Column(db.String(255), nullable=True)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    document_link = db.Column(db.String(500), nullable=True)
    target_unit = db.Column(db.String(50), default='Todas')
    is_urgent = db.Column(db.Boolean, default=False)
    publish_at = db.Column(db.DateTime, default=get_br_time)
    created_at = db.Column(db.DateTime, default=get_br_time)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    author = db.relationship('User', backref='announcements')
    views = db.relationship('AnnouncementView', backref='announcement', cascade='all, delete-orphan')
    files = db.relationship('AnnouncementFile', backref='announcement', cascade='all, delete-orphan')

class AnnouncementFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    announcement_id = db.Column(db.Integer, db.ForeignKey('announcement.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)

class AnnouncementView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    announcement_id = db.Column(db.Integer, db.ForeignKey('announcement.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    viewed_at = db.Column(db.DateTime, default=get_br_time)
    
    user = db.relationship('User')

class SavedPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_name = db.Column(db.String(100), nullable=False)
    service_url = db.Column(db.String(255), nullable=True)
    service_username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
    encrypted_notes = db.Column(db.LargeBinary, nullable=True)
    created_at = db.Column(db.DateTime, default=get_br_time)
    
    shares = db.relationship('SharedPassword', backref='saved_password', cascade='all, delete-orphan')

class SharedPassword(db.Model):
    """Credenciais compartilhadas entre usuários do sistema."""
    id = db.Column(db.Integer, primary_key=True)
    saved_password_id = db.Column(db.Integer, db.ForeignKey('saved_password.id', ondelete='CASCADE'), nullable=False)
    shared_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=get_br_time)
    
    sender = db.relationship('User', foreign_keys=[shared_by_user_id], backref='shared_by_me')
    recipient = db.relationship('User', foreign_keys=[shared_with_user_id], backref='shared_with_me')

class PasswordHistory(db.Model):
    """Histórico de alterações de uma credencial salva."""
    id = db.Column(db.Integer, primary_key=True)
    saved_password_id = db.Column(db.Integer, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_name = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # 'criada', 'alterada', 'removida'
    changed_by = db.Column(db.String(100), nullable=True)
    changed_at = db.Column(db.DateTime, default=get_br_time)

class UserNotification(db.Model):
    """Notificações diretas para o usuário (ex: alteração de senha compartilhada)."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), default='info') # 'shared_password_updated', 'shared_password_new', 'announcement', 'security'
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=get_br_time)
    
    user = db.relationship('User', backref=db.backref('user_notifications', lazy='dynamic', cascade='all, delete-orphan'))


class CompanyExtension(db.Model):
    """Lista oficial de ramais e contatos da Gama Caminhões."""
    __tablename__ = 'company_extension'
    id = db.Column(db.Integer, primary_key=True)
    unit = db.Column(db.String(50), nullable=False) # 'Campina Grande' ou 'João Pessoa'
    sector = db.Column(db.String(100), nullable=False)
    role_name = db.Column(db.String(100), nullable=True)
    name = db.Column(db.String(120), nullable=False)
    extension = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(150), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    display_order = db.Column(db.Integer, default=0)

class AuditLog(db.Model):
    """Log de auditoria global do sistema."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    username_at_time = db.Column(db.String(100), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(500), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=get_br_time)



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

@app.before_request
def update_user_ip_and_cleanup_avisos():
    # Remover avisos com mais de 7 dias
    limite = get_br_time() - timedelta(days=7)
    velhos = Announcement.query.filter(Announcement.created_at < limite).all()
    if velhos:
        for a in velhos:
            db.session.delete(a)
        db.session.commit()

@app.route('/api/atualizar_ip_local', methods=['POST'])
@login_required
def api_atualizar_ip_local():
    data = request.get_json(silent=True) or {}
    local_ip = (data.get('local_ip') or '').strip()
    if local_ip:
        # Se for um IP de rede interna privada (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
        # e o usuário ainda não tiver IP ou estiver com um IP público externo antigo
        if not current_user.machine_ip or not current_user.machine_ip.startswith(('10.', '192.168.', '172.')) or (local_ip.startswith('10.') and not current_user.machine_ip.startswith('10.')):
            current_user.machine_ip = local_ip
            db.session.commit()
    return {'status': 'ok'}

@app.context_processor
def inject_avisos():
    try:
        if current_user and getattr(current_user, 'is_authenticated', False):
            agora = get_br_time()
            if getattr(current_user, 'is_admin', False) or getattr(current_user, 'is_hr', False):
                avisos = Announcement.query.order_by(Announcement.is_urgent.desc(), Announcement.created_at.desc()).all()
            else:
                user_unit = (getattr(current_user, 'unit', '') or '').strip()
                avisos = Announcement.query.filter(
                    Announcement.publish_at <= agora,
                    db.or_(
                        Announcement.target_unit == 'Todas',
                        Announcement.target_unit == None,
                        Announcement.target_unit == '',
                        Announcement.target_unit == user_unit
                    )
                ).order_by(Announcement.is_urgent.desc(), Announcement.created_at.desc()).all()

            last_view = getattr(current_user, 'last_announcement_view', None) or datetime.min
            nao_lidos = [a for a in avisos if a.created_at and a.created_at > last_view]
            
            # Notificações individuais do usuário
            user_notifs = UserNotification.query.filter_by(user_id=current_user.id).order_by(UserNotification.created_at.desc()).limit(15).all()
            nao_lidos_user = [n for n in user_notifs if not n.is_read]
            
            total_nao_lidos = len(nao_lidos_user)  # O sino conta exclusivamente as notificações padronizadas
            
            return dict(
                global_avisos=avisos, 
                global_avisos_nao_lidos=nao_lidos,
                global_user_notifs=user_notifs,
                global_total_nao_lidos=total_nao_lidos
            )
    except Exception as ex:
        print(f"[AVISO inject_avisos]: {ex}")
    return dict(global_avisos=[], global_avisos_nao_lidos=[], global_user_notifs=[], global_total_nao_lidos=0)

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
    """Tenta enviar via API HTTPS (Brevo/Resend) ou SMTP com fallback em cascata."""
    erros = []

    # 1. Brevo API (HTTPS - Recomendado e funciona no Render sem bloqueio de portas)
    brevo_key = os.environ.get('BREVO_API_KEY', '').strip()
    if brevo_key:
        sucesso, msg_brevo = enviar_via_brevo(destinatario, assunto, corpo)
        if sucesso:
            return True, msg_brevo
        erros.append(f"Brevo ({msg_brevo})")
    
    # 2. SMTP direto (Gmail/Outlook)
    senha_email = os.environ.get('EMAIL_SENHA', '').strip()
    remetente = os.environ.get('EMAIL_REMETENTE', '').strip()
    
    if senha_email and senha_email != 'EMPTY_PASS' and remetente and remetente != 'email_padrao@empresa.com.br':
        msg = MIMEText(corpo, 'plain', 'utf-8')
        msg['Subject'] = assunto
        msg['From'] = f"GAMAPASS - Gama Caminhões <{remetente}>"
        msg['To'] = destinatario
        msg['Reply-To'] = remetente
        
        sucesso, msg_smtp = disparar_email_smtp(destinatario, msg)
        if sucesso:
            return True, msg_smtp
        erros.append(f"SMTP ({msg_smtp})")

    # 3. Resend API (HTTPS)
    resend_key = os.environ.get('RESEND_API_KEY', '').strip()
    if resend_key:
        sucesso, msg_resend = enviar_via_resend(destinatario, assunto, corpo)
        if sucesso:
            return True, msg_resend
        erros.append(f"Resend ({msg_resend})")

    if not erros:
        return False, "Nenhum método de envio configurado (configure BREVO_API_KEY no Render)."
        
    return False, " | ".join(erros)


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
        
        if user:
            # 1. Verifica se a conta está temporariamente bloqueada
            agora = get_br_time()
            if user.locked_until and user.locked_until > agora:
                minutos_restantes = max(1, int((user.locked_until - agora).total_seconds() / 60))
                registrar_auditoria('LOGIN_BLOQUEADO', f'Tentativa de acesso em conta bloqueada: "{username}". Bloqueio ativo por mais {minutos_restantes} min.')
                flash(f'Conta temporariamente bloqueada após 5 tentativas incorretas. Tente novamente em {minutos_restantes} minuto(s) ou solicite o desbloqueio ao Administrador de TI.', 'error')
                return render_template('login.html')

        if user and check_password_hash(user.password_hash, password):
            current_ip = get_client_ip()
            current_ua = (request.headers.get('User-Agent') or 'Desconhecido')[:250]
            
            # 2. Alerta de Segurança por E-mail (se login for de IP ou Navegador diferente do habitual)
            if user.email and (user.last_login_ip or user.last_user_agent):
                ip_mudou = user.last_login_ip and user.last_login_ip != current_ip
                ua_mudou = user.last_user_agent and user.last_user_agent != current_ua
                if ip_mudou or ua_mudou:
                    assunto = "⚠️ Alerta de Segurança - Novo Acesso Detectado no GAMAPASS"
                    corpo = (
                        f"Olá, {user.display_name or user.username}!\n\n"
                        f"Identificamos um novo acesso à sua conta no GAMAPASS a partir de um endereço IP ou dispositivo diferente do habitual:\n\n"
                        f"• Data e Hora: {get_br_time().strftime('%d/%m/%Y às %H:%M')}\n"
                        f"• Endereço IP: {current_ip}\n"
                        f"• Dispositivo / Navegador: {current_ua}\n\n"
                        f"Caso tenha sido você, não se preocupe! Esta é uma notificação automática de segurança.\n"
                        f"Caso NÃO reconheça este acesso, contate imediatamente o Administrador de TI para redefinir sua senha.\n\n"
                        f"Atenciosamente,\n"
                        f"Equipe de Tecnologia da Informação\n"
                        f"Gama Caminhões"
                    )
                    try:
                        enviar_email_geral(user.email, assunto, corpo)
                        registrar_auditoria('ALERTA_LOGIN_DISPOSITIVO', f'Alerta de novo acesso (IP: {current_ip}) enviado para {user.email}.')
                    except Exception as ex:
                        print(f"[ALERTA EMAIL ERROR]: {ex}")

            # Reseta tentativas e atualiza dados
            user.failed_login_attempts = 0
            user.locked_until = None
            user.last_login_ip = current_ip
            user.last_user_agent = current_ua
            user.last_login_date = get_br_time().strftime('%Y-%m-%d')
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()

            login_user(user)
            registrar_auditoria('LOGIN', f'Usuário {username} fez login com sucesso.')
            
            if user.requires_password_reset:
                return redirect(url_for('force_password_reset'))
            if user.is_first_login:
                return redirect(url_for('first_setup'))
            return redirect(url_for('dashboard'))
        else:
            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = get_br_time() + timedelta(minutes=15)
                    db.session.commit()
                    registrar_auditoria('CONTA_BLOQUEADA', f'Usuário "{username}" bloqueado por 15 minutos após 5 tentativas incorretas.')
                    flash('Conta bloqueada por 15 minutos após 5 tentativas incorretas de senha. Contate o Administrador de TI ou aguarde o tempo limite.', 'error')
                else:
                    tentativas_restantes = 5 - user.failed_login_attempts
                    db.session.commit()
                    registrar_auditoria('LOGIN_FALHA', f'Tentativa de login falhou para usuário: {username} ({user.failed_login_attempts}/5).')
                    flash(f'Credenciais inválidas. Você tem mais {tentativas_restantes} tentativa(s) antes do bloqueio da conta.', 'error')
            else:
                registrar_auditoria('LOGIN_FALHA', f'Tentativa de login falhou para usuário inexistente: {username}.')
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
        'email': current_user.email or ''
    }
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
        notes = request.form.get('notes', '').strip()
        encrypted_notes = cipher_suite.encrypt(notes.encode('utf-8')) if notes else None

        new_entry = SavedPassword(
            user_id=current_user.id, 
            service_name=service, 
            service_url=service_url, 
            service_username=service_user, 
            encrypted_password=encrypted_pw,
            encrypted_notes=encrypted_notes
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

    saved_entries = SavedPassword.query.filter_by(user_id=current_user.id).order_by(SavedPassword.id.desc()).all()
    decrypted_entries = []
    for entry in saved_entries:
        try:
            decrypted_pw = cipher_suite.decrypt(entry.encrypted_password).decode('utf-8')
        except Exception:
            decrypted_pw = "[Erro ao descriptografar]"
            
        decrypted_notes = ""
        if entry.encrypted_notes:
            try:
                decrypted_notes = cipher_suite.decrypt(entry.encrypted_notes).decode('utf-8')
            except Exception:
                decrypted_notes = "[Erro ao descriptografar notas]"
                
        shares_info = [{
            'id': s.id,
            'recipient_username': s.recipient.username if s.recipient else 'Usuário',
            'recipient_name': s.recipient.display_name or s.recipient.username if s.recipient else 'Usuário',
            'created_at': s.created_at.strftime('%d/%m/%Y às %H:%M') if s.created_at else ''
        } for s in entry.shares]

        decrypted_entries.append({
            'id': entry.id, 
            'service_name': entry.service_name, 
            'service_url': entry.service_url, 
            'service_username': entry.service_username, 
            'password': decrypted_pw,
            'notes': decrypted_notes,
            'shares': shares_info
        })

    # Credenciais compartilhadas com o usuário atual
    shared_with_me_records = SharedPassword.query.filter_by(shared_with_user_id=current_user.id).order_by(SharedPassword.id.desc()).all()
    shared_entries = []
    for s in shared_with_me_records:
        entry = s.saved_password
        if not entry:
            continue
        try:
            decrypted_pw = cipher_suite.decrypt(entry.encrypted_password).decode('utf-8')
        except Exception:
            decrypted_pw = "[Erro ao descriptografar]"
        decrypted_notes = ""
        if entry.encrypted_notes:
            try:
                decrypted_notes = cipher_suite.decrypt(entry.encrypted_notes).decode('utf-8')
            except Exception:
                decrypted_notes = ""
                
        shared_entries.append({
            'share_id': s.id,
            'password_id': entry.id,
            'service_name': entry.service_name,
            'service_url': entry.service_url,
            'service_username': entry.service_username,
            'password': decrypted_pw,
            'notes': decrypted_notes,
            'sender_username': s.sender.username if s.sender else 'Usuário',
            'sender_name': s.sender.display_name or s.sender.username if s.sender else 'Usuário',
            'shared_at': s.created_at.strftime('%d/%m/%Y às %H:%M') if s.created_at else ''
        })
        
    agora = get_br_time()
    if current_user.is_admin or current_user.is_hr:
        avisos = Announcement.query.order_by(Announcement.is_urgent.desc(), Announcement.created_at.desc()).all()
    else:
        user_unit = (current_user.unit or '').strip()
        avisos = Announcement.query.filter(
            Announcement.publish_at <= agora,
            db.or_(
                Announcement.target_unit == 'Todas',
                Announcement.target_unit == None,
                Announcement.target_unit == '',
                Announcement.target_unit == user_unit
            )
        ).order_by(Announcement.is_urgent.desc(), Announcement.created_at.desc()).all()
    
    # Avisos não lidos
    from datetime import datetime
    last_view = current_user.last_announcement_view or datetime.min
    avisos_nao_lidos = [a for a in avisos if a.created_at > last_view]
        
    if CompanyExtension.query.count() == 0:
        inicializar_ramais()
    ramais_db = CompanyExtension.query.order_by(CompanyExtension.unit.asc(), CompanyExtension.sector.asc(), CompanyExtension.name.asc()).all()
    return render_template('dashboard.html', 
        entries=decrypted_entries, 
        shared_entries=shared_entries,
        avisos=avisos, 
        avisos_nao_lidos=avisos_nao_lidos,
        ramais=ramais_db
    )

@app.route('/compartilhar_senha/<int:pass_id>', methods=['POST'])
@login_required
def compartilhar_senha(pass_id):
    entry = SavedPassword.query.get_or_404(pass_id)
    if entry.user_id != current_user.id:
        flash('Acesso negado. Você só pode compartilhar suas próprias credenciais.', 'error')
        return redirect(url_for('dashboard'))
        
    destinatario_username = request.form.get('recipient_username', '').strip()
    if not destinatario_username:
        flash('Informe o login do usuário de destino para compartilhar.', 'error')
        return redirect(url_for('dashboard'))
        
    if destinatario_username.lower() == current_user.username.lower():
        flash('Você não pode compartilhar uma credencial com você mesmo.', 'error')
        return redirect(url_for('dashboard'))
        
    destinatario = User.query.filter(User.username.ilike(destinatario_username)).first()
    if not destinatario:
        flash(f'Usuário "{destinatario_username}" não encontrado no sistema.', 'error')
        return redirect(url_for('dashboard'))
        
    # Verifica se já está compartilhado
    ja_compartilhado = SharedPassword.query.filter_by(
        saved_password_id=entry.id,
        shared_with_user_id=destinatario.id
    ).first()
    
    if ja_compartilhado:
        flash(f'Esta credencial já está compartilhada com "{destinatario.username}".', 'warning')
        return redirect(url_for('dashboard'))
        
    novo_compartilhamento = SharedPassword(
        saved_password_id=entry.id,
        shared_by_user_id=current_user.id,
        shared_with_user_id=destinatario.id
    )
    db.session.add(novo_compartilhamento)
    
    # Cria notificação individual para o destinatário
    remetente_nome = current_user.display_name or current_user.username
    notif = UserNotification(
        user_id=destinatario.id,
        title=f"Nova Credencial: {entry.service_name}",
        message=f"{remetente_nome} compartilhou com você o acesso ao serviço '{entry.service_name}'.",
        notification_type='shared_password_new'
    )
    db.session.add(notif)
    db.session.commit()
    
    registrar_auditoria('SENHA_COMPARTILHADA', f'Usuário "{current_user.username}" compartilhou a credencial "{entry.service_name}" com "{destinatario.username}".')
    flash(f'Credencial "{entry.service_name}" compartilhada com sucesso com "{destinatario.display_name or destinatario.username}"!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/revogar_compartilhamento/<int:share_id>', methods=['POST'])
@login_required
def revogar_compartilhamento(share_id):
    share = SharedPassword.query.get_or_404(share_id)
    if share.shared_by_user_id != current_user.id and share.shared_with_user_id != current_user.id and not current_user.is_admin:
        flash('Acesso negado.', 'error')
        return redirect(url_for('dashboard'))
        
    service_name = share.saved_password.service_name if share.saved_password else 'Credencial'
    recipient_name = share.recipient.username if share.recipient else 'usuário'
    db.session.delete(share)
    db.session.commit()
    
    registrar_auditoria('COMPARTILHAMENTO_REVOGADO', f'Compartilhamento da credencial "{service_name}" com "{recipient_name}" foi revogado.')
    flash('Compartilhamento revogado com sucesso!', 'success')
    return redirect(url_for('dashboard'))

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
        
    notes = request.form.get('notes', '').strip()
    entry.encrypted_notes = cipher_suite.encrypt(notes.encode('utf-8')) if notes else None

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
        
        # Notifica todos os membros que possuem acesso compartilhado a esta credencial
        if entry.shares:
            remetente_nome = current_user.display_name or current_user.username
            for share in entry.shares:
                notif = UserNotification(
                    user_id=share.shared_with_user_id,
                    title=f"Senha Atualizada: {entry.service_name}",
                    message=f"A credencial do serviço '{entry.service_name}' compartilhada por {remetente_nome} foi alterada.",
                    notification_type='shared_password_updated'
                )
                db.session.add(notif)
                
                # Disparo de e-mail informativo se o destinatário tiver e-mail
                if share.recipient and share.recipient.email:
                    assunto_email = f"🔔 Atualização de Credencial Compartilhada - {entry.service_name}"
                    corpo_email = (
                        f"Olá, {share.recipient.display_name or share.recipient.username}!\n\n"
                        f"Informamos que os dados de acesso da credencial do serviço \"{entry.service_name}\" compartilhada por {remetente_nome} no GAMAPASS foram atualizados.\n\n"
                        f"Os novos dados já podem ser consultados no cofre na seção 'Credenciais Compartilhadas Comigo'.\n\n"
                        f"Atenciosamente,\n"
                        f"GAMAPASS - Gama Caminhões"
                    )
                    try:
                        enviar_email_geral(share.recipient.email, assunto_email, corpo_email)
                    except Exception as ex:
                        print(f"[EMAIL NOTIF ERROR]: {ex}")

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
def extrair_nome_servico_url(url, fallback=""):
    if not url:
        return fallback or "Serviço Web"
    try:
        u = url.strip()
        if not u.startswith(('http://', 'https://')):
            u = 'https://' + u
        parsed = urlparse(u)
        host = parsed.netloc or parsed.path
        host = host.split(':')[0]
        partes = host.split('.')
        if len(partes) >= 2:
            if partes[0].lower() in ['www', 'login', 'accounts', 'auth', 'app', 'portal', 'web', 'mail', 'm', 'poc']:
                return partes[1].capitalize()
            elif len(partes) >= 3 and partes[-2].lower() in ['com', 'org', 'net', 'gov', 'edu', 'ind', 'br', 'io', 'app']:
                return partes[-3].capitalize()
            else:
                return partes[0].capitalize()
        return host.capitalize()
    except Exception:
        return fallback or url

def classificar_coluna_csv(col_raw):
    col = str(col_raw).strip().lower().replace('_', '').replace(' ', '').replace('-', '').replace('"', '')
    
    # 1. Ignorar metadados e colunas que contenham termos enganosos (ex: timepasswordchanged, formActionOrigin)
    if any(ign in col for ign in ['time', 'date', 'changed', 'created', 'used', 'guid', 'realm', 'origin', 'favorite', 'reprompt', 'otp', 'totp', 'action']):
        if col not in ['datadecadastro']:
            return 'ignorar'
            
    # 2. Senha (Password)
    if col in ['password', 'senha', 'pass', 'loginpassword', 'pwd']:
        return 'password'
        
    # 3. Usuário / Login / Email
    if col in ['username', 'usuario', 'usuário', 'login', 'loginusername', 'loginname', 'user', 'email', 'e-mail', 'account']:
        return 'username'
        
    # 4. URL / Link / Site
    if col in ['url', 'link', 'website', 'loginuri', 'uri', 'site', 'origem', 'hostname']:
        return 'url'
        
    # 5. Nome do Serviço / Título
    if col in ['name', 'title', 'titulo', 'título', 'servico', 'serviço', 'service', 'nome', 'accountname', 'grouping', 'folder']:
        return 'service'
        
    # 6. Notas / Observações
    if col in ['note', 'notes', 'notas', 'observacoes', 'observações', 'comments', 'extra']:
        return 'notes'
        
    # Fallbacks flexíveis
    if 'pass' in col or 'senha' in col:
        return 'password'
    if 'user' in col or 'usuario' in col or 'login' in col:
        return 'username'
    if 'url' in col or 'link' in col or 'site' in col:
        return 'url'
    if 'serv' in col or 'title' in col or 'name' in col or 'titul' in col:
        return 'service'
        
    return 'desconhecido'

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
        separador = ';' if primeira_linha.count(';') > primeira_linha.count(',') else ','
        if '\t' in primeira_linha and primeira_linha.count('\t') > max(primeira_linha.count(','), primeira_linha.count(';')):
            separador = '\t'
            
        stream = io.StringIO(conteudo, newline=None)
        csv_input = csv.DictReader(stream, delimiter=separador)
        senhas_extraidas = []

        for row in csv_input:
            senha = ''
            usuario = ''
            url = ''
            servico = ''
            notas = ''
            
            for chave, valor in row.items():
                if not chave or valor is None:
                    continue
                v = str(valor).strip()
                tipo = classificar_coluna_csv(chave)
                
                if tipo == 'password':
                    senha = v
                elif tipo == 'username':
                    usuario = v
                elif tipo == 'url':
                    url = v
                elif tipo == 'service':
                    servico = v
                elif tipo == 'notes':
                    notas = v

            if not senha:
                continue

            if not servico and url:
                servico = extrair_nome_servico_url(url)
            elif not servico:
                servico = "Serviço Web"

            senhas_extraidas.append({
                'servico': servico,
                'usuario': usuario,
                'senha': senha,
                'url': url,
                'notas': notas
            })

        if len(senhas_extraidas) == 0:
            flash('Nenhuma credencial ou senha válida foi identificada no arquivo CSV.', 'warning')
            return redirect(url_for('dashboard'))
            
        return render_template('revisar_importacao.html', senhas=senhas_extraidas)
        
    except Exception as e:
        flash(f'Erro ao processar arquivo CSV: {e}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/salvar-importacao', methods=['POST'])
@login_required
def salvar_importacao():
    servicos = request.form.getlist('servicos[]')
    usuarios = request.form.getlist('usuarios[]')
    senhas = request.form.getlist('senhas[]')
    urls = request.form.getlist('urls[]')
    notas_list = request.form.getlist('notas[]')
    
    senhas_salvas = 0
    senhas_duplicadas = 0
    try:
        for i in range(len(servicos)):
            servico = servicos[i].strip()
            usuario = usuarios[i].strip() if i < len(usuarios) else ''
            senha = senhas[i] if i < len(senhas) else ''
            url = urls[i].strip() if i < len(urls) else ''
            nota = notas_list[i].strip() if i < len(notas_list) else ''
            
            if not servico or not senha:
                continue
                
            duplicado = SavedPassword.query.filter_by(
                user_id=current_user.id, 
                service_name=servico, 
                service_username=usuario
            ).first()
            if duplicado:
                senhas_duplicadas += 1
                continue
                
            senha_criptografada = cipher_suite.encrypt(senha.encode('utf-8'))
            encrypted_notes = cipher_suite.encrypt(nota.encode('utf-8')) if nota else None
            
            nova_senha = SavedPassword(
                user_id=current_user.id, 
                service_name=servico, 
                service_username=usuario, 
                encrypted_password=senha_criptografada, 
                service_url=url,
                encrypted_notes=encrypted_notes
            )
            db.session.add(nova_senha)
            db.session.flush()
            
            # Registra no histórico
            hist = PasswordHistory(
                saved_password_id=nova_senha.id,
                user_id=current_user.id,
                service_name=servico,
                action='importada',
                changed_by=current_user.username
            )
            db.session.add(hist)
            senhas_salvas += 1
            
        db.session.commit()
        msg = f'{senhas_salvas} credenciais importadas e protegidas no cofre com sucesso!'
        if senhas_duplicadas > 0:
            msg += f' ({senhas_duplicadas} credenciais já existiam no cofre e foram mantidas sem duplicar).'
        flash(msg, 'success')
        registrar_auditoria('IMPORTACAO_CSV', f'{senhas_salvas} credenciais importadas via CSV por "{current_user.username}".')
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

    users = User.query.order_by(User.id.desc()).all()
    
    # Cálculo de Métricas Gerenciais
    total_users = len(users)
    users_campina = sum(1 for u in users if (u.unit or '').strip().lower() == 'campina grande')
    users_jp = sum(1 for u in users if (u.unit or '').strip().lower() in ['joão pessoa', 'joao pessoa'])
    users_outros = total_users - (users_campina + users_jp)
    
    users_ativos = sum(1 for u in users if not u.is_first_login)
    taxa_adesao = round((users_ativos / total_users * 100), 1) if total_users > 0 else 0
    
    # Auditoria de Força de Senhas Global
    all_passwords = SavedPassword.query.all()
    total_senhas = len(all_passwords)
    senhas_fracas = 0
    senhas_medias = 0
    senhas_fortes = 0
    
    for p in all_passwords:
        try:
            plain = cipher_suite.decrypt(p.encrypted_password).decode('utf-8')
            score = 0
            if len(plain) >= 8: score += 1
            if len(plain) >= 12: score += 1
            if re.search(r'[A-Z]', plain): score += 1
            if re.search(r'[a-z]', plain): score += 1
            if re.search(r'[0-9]', plain): score += 1
            if re.search(r'[!@#$%*|&_+\-=.,;:?]', plain): score += 1
            if score <= 2:
                senhas_fracas += 1
            elif score in (3, 4):
                senhas_medias += 1
            else:
                senhas_fortes += 1
        except Exception:
            pass
            
    metricas = {
        'total_users': total_users,
        'users_campina': users_campina,
        'users_jp': users_jp,
        'users_outros': users_outros,
        'users_ativos': users_ativos,
        'taxa_adesao': taxa_adesao,
        'total_senhas': total_senhas,
        'senhas_fracas': senhas_fracas,
        'senhas_medias': senhas_medias,
        'senhas_fortes': senhas_fortes
    }

    return render_template('admin.html', users=users, metricas=metricas, agora=get_br_time())

@app.route('/admin/desbloquear_usuario/<int:user_id>', methods=['POST'])
@login_required
def admin_desbloquear_usuario(user_id):
    if not current_user.is_admin:
        flash('Acesso negado.', 'error')
        return redirect(url_for('dashboard'))
        
    usuario = User.query.get_or_404(user_id)
    usuario.failed_login_attempts = 0
    usuario.locked_until = None
    db.session.commit()
    
    registrar_auditoria('USUARIO_DESBLOQUEADO', f'O Administrador "{current_user.username}" desbloqueou manualmente a conta de "{usuario.username}".')
    flash(f"Conta de '{usuario.username}' desbloqueada com sucesso!", 'success')
    return redirect(url_for('admin_panel'))

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

def obter_logs_auditoria_filtrados(args):
    filtro_usuario = args.get('usuario', '').strip()
    filtro_acao = args.get('acao', '').strip()
    filtro_unidade = args.get('unidade', '').strip()
    filtro_departamento = args.get('departamento', '').strip()
    data_inicio_str = args.get('data_inicio', '').strip()
    data_fim_str = args.get('data_fim', '').strip()

    query = AuditLog.query
    
    if filtro_usuario:
        query = query.filter(AuditLog.username_at_time.ilike(f'%{filtro_usuario}%'))
    if filtro_acao:
        query = query.filter(AuditLog.action == filtro_acao)
        
    if data_inicio_str:
        try:
            d_ini = datetime.strptime(data_inicio_str, '%Y-%m-%d')
            query = query.filter(AuditLog.created_at >= d_ini)
        except Exception:
            pass
            
    if data_fim_str:
        try:
            d_fim = datetime.strptime(data_fim_str + " 23:59:59", '%Y-%m-%d %H:%M:%S')
            query = query.filter(AuditLog.created_at <= d_fim)
        except Exception:
            pass

    if filtro_unidade or filtro_departamento:
        u_query = User.query
        if filtro_unidade:
            u_query = u_query.filter(User.unit == filtro_unidade)
        if filtro_departamento:
            u_query = u_query.filter(User.department.ilike(f'%{filtro_departamento}%'))
        matching_users = u_query.all()
        matching_ids = [u.id for u in matching_users]
        matching_unames = [u.username for u in matching_users]
        query = query.filter(
            db.or_(
                AuditLog.user_id.in_(matching_ids),
                AuditLog.username_at_time.in_(matching_unames)
            )
        )
        
    filtros = {
        'usuario': filtro_usuario,
        'acao': filtro_acao,
        'unidade': filtro_unidade,
        'departamento': filtro_departamento,
        'data_inicio': data_inicio_str,
        'data_fim': data_fim_str
    }
    return query, filtros


# ================= ROTAS DE GESTÃO DE RAMAIS =================
@app.route('/ramais/adicionar', methods=['POST'])
@login_required
def ramais_adicionar():
    if not (current_user.is_admin or current_user.is_hr):
        flash('Acesso restrito ao RH e Administradores.', 'error')
        return redirect(url_for('dashboard'))
        
    unit = request.form.get('unit', '').strip() or 'Campina Grande'
    sector = request.form.get('sector', '').strip().upper()
    role_name = request.form.get('role_name', '').strip().upper()
    name = request.form.get('name', '').strip().upper()
    extension = request.form.get('extension', '').strip() or '-'
    email = request.form.get('email', '').strip() or '-'
    phone = request.form.get('phone', '').strip() or '-'
    
    if not name or not sector:
        flash('Nome e Setor são obrigatórios.', 'error')
        return redirect(url_for('dashboard'))
        
    novo_ramal = CompanyExtension(
        unit=unit,
        sector=sector,
        role_name=role_name,
        name=name,
        extension=extension,
        email=email,
        phone=phone
    )
    db.session.add(novo_ramal)
    db.session.commit()
    registrar_auditoria('RAMAL_ADICIONADO', f'O RH/Admin "{current_user.username}" adicionou o contato "{name}" ({unit} - Ramal {extension}).')
    flash(f'Contato "{name}" adicionado à lista de ramais com sucesso!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/ramais/editar/<int:ramal_id>', methods=['POST'])
@login_required
def ramais_editar(ramal_id):
    if not (current_user.is_admin or current_user.is_hr):
        flash('Acesso restrito ao RH e Administradores.', 'error')
        return redirect(url_for('dashboard'))
        
    ramal = CompanyExtension.query.get_or_404(ramal_id)
    ramal.unit = request.form.get('unit', ramal.unit).strip()
    ramal.sector = request.form.get('sector', ramal.sector).strip().upper()
    ramal.role_name = request.form.get('role_name', ramal.role_name).strip().upper()
    ramal.name = request.form.get('name', ramal.name).strip().upper()
    ramal.extension = request.form.get('extension', ramal.extension).strip() or '-'
    ramal.email = request.form.get('email', ramal.email).strip() or '-'
    ramal.phone = request.form.get('phone', ramal.phone).strip() or '-'
    
    db.session.commit()
    registrar_auditoria('RAMAL_EDITADO', f'O RH/Admin "{current_user.username}" atualizou as informações do contato "{ramal.name}".')
    flash(f'Contato "{ramal.name}" atualizado com sucesso!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/ramais/deletar/<int:ramal_id>', methods=['POST'])
@login_required
def ramais_deletar(ramal_id):
    if not (current_user.is_admin or current_user.is_hr):
        flash('Acesso restrito ao RH e Administradores.', 'error')
        return redirect(url_for('dashboard'))
        
    ramal = CompanyExtension.query.get_or_404(ramal_id)
    nome = ramal.name
    db.session.delete(ramal)
    db.session.commit()
    registrar_auditoria('RAMAL_REMOVIDO', f'O RH/Admin "{current_user.username}" removeu o contato "{nome}" da lista de ramais.')
    flash(f'Contato "{nome}" removido com sucesso!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/ramais/exportar_pdf')
@login_required
def exportar_ramais_pdf():
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    import io
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=25, leftMargin=25, topMargin=25, bottomMargin=25)
    elements = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=18,
        alignment=1,
        textColor=colors.HexColor('#0b1329')
    )
    subtitle_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        alignment=1,
        textColor=colors.HexColor('#475569')
    )
    pabx_style = ParagraphStyle(
        'PabxStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        alignment=1,
        textColor=colors.HexColor('#166534')
    )
    
    elements.append(Paragraph("<b>GAMA CAMINHÕES & ÔNIBUS — LISTA DE RAMAIS OFICIAL</b>", title_style))
    elements.append(Paragraph(f"Atualização Oficial do RH: {get_br_time().strftime('%d/%m/%Y às %H:%M')}", subtitle_style))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph("<b>PABX:</b> Transferir: FLASH + RAMAL | Retornar se ocupado: FLASH + # + 0 | Atender específico: # + 5 RAMAL + * | Atender qualquer: FLASH + 22<br/><b>Campina Grande:</b> (83) 3315-4500 | <b>João Pessoa:</b> (83) 3215-5666", pabx_style))
    elements.append(Spacer(1, 8))
    
    ramais = CompanyExtension.query.order_by(CompanyExtension.unit.asc(), CompanyExtension.sector.asc(), CompanyExtension.name.asc()).all()
    
    data = [["Unidade", "Setor / Cargo", "Nome", "Ramal", "E-mail", "Celular"]]
    
    cell_style = ParagraphStyle('Cell', fontName='Helvetica', fontSize=7.5, leading=9.5)
    cell_bold = ParagraphStyle('CellB', fontName='Helvetica-Bold', fontSize=7.5, leading=9.5)
    cell_ext = ParagraphStyle('CellExt', fontName='Helvetica-Bold', fontSize=8.5, leading=10.5, alignment=1, textColor=colors.HexColor('#1d4ed8'))
    
    for r in ramais:
        u_short = "Campina Grande" if "CAMPINA" in r.unit.upper() else "João Pessoa"
        setor_txt = f"<b>{r.sector}</b><br/>{r.role_name or ''}"
        data.append([
            Paragraph(u_short, cell_style),
            Paragraph(setor_txt, cell_style),
            Paragraph(f"<b>{r.name}</b>", cell_bold),
            Paragraph(r.extension or "-", cell_ext),
            Paragraph(r.email or "-", cell_style),
            Paragraph(r.phone or "-", cell_style)
        ])
    
    col_widths = [75, 110, 110, 45, 125, 80]
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0b1329')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 4),
        ('TOPPADDING', (0, 0), (-1, 0), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    
    elements.append(t)
    doc.build(elements)
    buffer.seek(0)
    
    return Response(
        buffer.getvalue(),
        mimetype='application/pdf',
        headers={"Content-Disposition": "attachment; filename=Lista_de_Ramais_Gama_Caminhoes.pdf"}
    )

@app.route('/admin/auditoria')
@login_required
def admin_auditoria():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    query, filtros = obter_logs_auditoria_filtrados(request.args)
    logs = query.order_by(AuditLog.created_at.desc()).limit(500).all()
    
    usuarios = db.session.query(AuditLog.username_at_time).distinct().all()
    acoes_distintas = db.session.query(AuditLog.action).distinct().all()
    departamentos = [d[0] for d in db.session.query(User.department).distinct().all() if d[0]]
    
    return render_template('auditoria.html',
        logs=logs,
        filtros=filtros,
        usuarios=[u[0] for u in usuarios if u[0]],
        acoes=[a[0] for a in acoes_distintas if a[0]],
        departamentos=departamentos
    )

@app.route('/admin/exportar_auditoria')
@login_required
def exportar_auditoria():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    query, _ = obter_logs_auditoria_filtrados(request.args)
    logs = query.order_by(AuditLog.created_at.desc()).all()
    
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
    resposta.headers["Content-Disposition"] = "attachment; filename=gamapass_relatorio_auditoria.csv"
    return resposta

# ================= PAINEL DE RH E AVISOS =================
@app.route('/rh')
@login_required
def rh_panel():
    if not (current_user.is_admin or current_user.is_hr):
        flash('Acesso negado. Esta área é restrita ao RH ou Administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    avisos = Announcement.query.order_by(Announcement.is_urgent.desc(), Announcement.created_at.desc()).all()
    return render_template('rh_panel.html', avisos=avisos, agora=get_br_time())

@app.route('/rh/aviso/novo', methods=['POST'])
@login_required
def rh_novo_aviso():
    if not (current_user.is_admin or current_user.is_hr):
        return redirect(url_for('dashboard'))
    
    titulo = request.form.get('titulo')
    conteudo = request.form.get('conteudo')
    document_link = request.form.get('document_link')
    target_unit = request.form.get('target_unit', 'Todas')
    is_urgent = request.form.get('is_urgent') == 'on'
    
    publish_at_str = request.form.get('publish_at', '').strip()
    publish_at = get_br_time()
    if publish_at_str:
        try:
            publish_at = datetime.strptime(publish_at_str, '%Y-%m-%dT%H:%M')
        except Exception:
            try:
                publish_at = datetime.fromisoformat(publish_at_str)
            except Exception:
                publish_at = get_br_time()
    
    if titulo and conteudo:
        aviso = Announcement(
            title=titulo, 
            content=conteudo, 
            document_link=document_link, 
            author_id=current_user.id,
            target_unit=target_unit,
            is_urgent=is_urgent,
            publish_at=publish_at
        )
        db.session.add(aviso)
        db.session.commit()
        
        arquivos = request.files.getlist('arquivos')
        count = 1
        for arquivo in arquivos:
            if arquivo and arquivo.filename:
                ext = arquivo.filename.rsplit('.', 1)[-1] if '.' in arquivo.filename else ''
                # Se for mais de um arquivo, anexa o contador
                if len(arquivos) > 1 and count > 1:
                    novo_nome = f"{titulo}_{count}.{ext}" if ext else f"{titulo}_{count}"
                else:
                    novo_nome = f"{titulo}.{ext}" if ext else titulo
                
                file_data = arquivo.read()
                novo_arq = AnnouncementFile(
                    announcement_id=aviso.id,
                    filename=novo_nome,
                    file_data=file_data
                )
                db.session.add(novo_arq)
                count += 1
        db.session.commit()
        status_msg = "urgente " if is_urgent else ""
        nome_autor = current_user.display_name or current_user.username
        if is_urgent:
            msg_notif = f"Um novo aviso foi adicionado por {nome_autor} e tem caráter urgente."
        else:
            msg_notif = f"Um novo aviso foi adicionado por {nome_autor}."
            
        usuarios = User.query.all()
        for u in usuarios:
            if u.id == current_user.id:
                continue
            if target_unit and target_unit != 'Todas' and (u.unit or '').strip() != target_unit and not (u.is_admin or u.is_hr):
                continue
            notif = UserNotification(
                user_id=u.id,
                title="Aviso do RH",
                message=msg_notif,
                notification_type='announcement'
            )
            db.session.add(notif)
        db.session.commit()
        status_msg = "urgente " if is_urgent else ""
        registrar_auditoria('AVISO_CRIADO', f'O RH/Admin "{current_user.username}" publicou um aviso {status_msg}para "{target_unit}": "{titulo}".')
        flash('Aviso publicado com sucesso!', 'success')
    else:
        flash('Título e conteúdo são obrigatórios.', 'error')
        
    return redirect(url_for('rh_panel'))

@app.route('/rh/aviso/editar/<int:aviso_id>', methods=['POST'])
@login_required
def rh_editar_aviso(aviso_id):
    if not (current_user.is_admin or current_user.is_hr):
        return redirect(url_for('dashboard'))
        
    aviso = Announcement.query.get_or_404(aviso_id)
    titulo = request.form.get('titulo')
    conteudo = request.form.get('conteudo')
    document_link = request.form.get('document_link')
    target_unit = request.form.get('target_unit', 'Todas')
    is_urgent = request.form.get('is_urgent') == 'on'
    
    publish_at_str = request.form.get('publish_at', '').strip()
    if publish_at_str:
        try:
            aviso.publish_at = datetime.strptime(publish_at_str, '%Y-%m-%dT%H:%M')
        except Exception:
            try:
                aviso.publish_at = datetime.fromisoformat(publish_at_str)
            except Exception:
                pass
    
    if titulo and conteudo:
        aviso.title = titulo
        aviso.content = conteudo
        aviso.document_link = document_link
        aviso.target_unit = target_unit
        aviso.is_urgent = is_urgent
        
        # Opcional: lidar com novos arquivos
        arquivos = request.files.getlist('arquivos')
        if arquivos and arquivos[0].filename:
            # Apaga antigos ou mantém? O usuário pediu só pra editar com erro. Vamos apagar os antigos e botar os novos.
            for f in aviso.files:
                db.session.delete(f)
            
            count = 1
            for arquivo in arquivos:
                if arquivo and arquivo.filename:
                    ext = arquivo.filename.rsplit('.', 1)[-1] if '.' in arquivo.filename else ''
                    if len(arquivos) > 1 and count > 1:
                        novo_nome = f"{titulo}_{count}.{ext}" if ext else f"{titulo}_{count}"
                    else:
                        novo_nome = f"{titulo}.{ext}" if ext else titulo
                        
                    file_data = arquivo.read()
                    novo_arq = AnnouncementFile(
                        announcement_id=aviso.id,
                        filename=novo_nome,
                        file_data=file_data
                    )
                    db.session.add(novo_arq)
                    count += 1
        
        db.session.commit()
        registrar_auditoria('AVISO_EDITADO', f'O RH/Admin "{current_user.username}" editou o aviso: "{titulo}".')
        flash('Aviso atualizado com sucesso!', 'success')
    else:
        flash('Título e conteúdo são obrigatórios para editar.', 'error')
        
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

@app.route('/api/notificacoes_status')
@login_required
def api_notificacoes_status():
    # Retorna EXCLUSIVAMENTE as notificações padronizadas do sino para o usuário
    user_notifs = UserNotification.query.filter_by(user_id=current_user.id).order_by(UserNotification.created_at.desc()).limit(20).all()
    unread_user_notifs = [n for n in user_notifs if not n.is_read]
    total_unseen = len(unread_user_notifs)
    
    latest_timestamp = 0
    for n in unread_user_notifs:
        if n.created_at:
            latest_timestamp = max(latest_timestamp, int(n.created_at.timestamp()))
            
    items = []
    for n in user_notifs:
        items.append({
            'id': n.id,
            'message': n.message,
            'is_read': n.is_read,
            'time': n.created_at.strftime('%d/%m/%Y às %H:%M') if n.created_at else ''
        })
        
    return {
        'total_unseen': total_unseen,
        'latest_timestamp': latest_timestamp,
        'items': items
    }

@app.route('/api/marcar_avisos_lidos', methods=['POST'])
@login_required
def marcar_avisos_lidos():
    current_user.last_announcement_view = get_br_time()
    UserNotification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    return {'status': 'ok'}

@app.route('/api/registrar_leitura/<int:aviso_id>', methods=['POST'])
@login_required
def registrar_leitura(aviso_id):
    # Verifica se já registrou para não duplicar muito
    existente = AnnouncementView.query.filter_by(announcement_id=aviso_id, user_id=current_user.id).first()
    if not existente:
        nova_view = AnnouncementView(announcement_id=aviso_id, user_id=current_user.id)
        db.session.add(nova_view)
        db.session.commit()
    else:
        existente.viewed_at = get_br_time()
        db.session.commit()
    return {'status': 'ok'}

@app.route('/aviso/arquivo/<int:file_id>')
@login_required
def baixar_arquivo_aviso(file_id):
    arq = AnnouncementFile.query.get_or_404(file_id)
    # Registrar leitura do aviso ao qual o arquivo pertence
    registrar_leitura(arq.announcement_id)
    return send_file(io.BytesIO(arq.file_data), download_name=arq.filename, as_attachment=False)

# ================= INICIALIZAÇÃO DO BANCO E MIGRAÇÃO AUTOMÁTICA =================

def inicializar_ramais():
    """Popula a lista oficial de ramais da Gama Caminhões no primeiro boot."""
    try:
        if CompanyExtension.query.count() == 0:
            dados_iniciais = [
                # CAMPINA GRANDE
                ("Campina Grande", "DIRETORIA", "DIREÇÃO", "ANDRÉ GAMA", "5654", "andre@gamacaminhoes.com.br", "(83) 98844-5096"),
                ("Campina Grande", "RECURSOS HUMANOS", "RH", "KARINA", "4524", "rh@gamacaminhoes.com.br", "(83) 99679-0145"),
                ("Campina Grande", "TÉCNICO DE INFORMÁTICA", "TI", "ERICK", "-", "informatica@gamacaminhoes.com.br", "(83) 98877-0263"),
                ("Campina Grande", "TÉCNICO DE INFORMÁTICA", "ESTAGIÁRIO DE TI", "JONATHAN", "-", "aux.informatica@gamacaminhoes.com.br", "(83) 99944-0467"),
                ("Campina Grande", "CRÉDITO E COBRANÇA", "CRÉDITO E COBRANÇA", "GERLANDIA", "4525", "creditoecobranca@gamacaminhoes.com.br", "(83) 99609-5222"),
                ("Campina Grande", "CONTABILIDADE", "GESTORA", "DAYSE", "5658", "contabilidade@gamacaminhoes.com.br", "(83) 99135-0151"),
                ("Campina Grande", "CONTABILIDADE", "RH", "ANA", "5651", "analistarh@gamaautos.com.br", "(83) 99135-0151"),
                ("Campina Grande", "CONTABILIDADE", "ASSISTENTE CONTÁBIL", "PRISCILA", "5651", "contabilidade04@gamacaminhoes.com.br", "(83) 99135-0151"),
                ("Campina Grande", "CONTABILIDADE", "ASSISTENTE CONTÁBIL", "ALANNA", "5651", "contabilidade02@gamacaminhoes.com.br", "(83) 99135-0151"),
                ("Campina Grande", "CONTABILIDADE", "ASSISTENTE CONTÁBIL", "TAMIRES", "5651", "contabilidade01@gamacaminhoes.com.br", "(83) 99135-0151"),
                ("Campina Grande", "CONTABILIDADE", "ASSIST. DE QUALIDADE", "ANDRIELLI", "5651", "qualidade@gamacaminhoes.com.br", "(83) 99837-0014"),
                ("Campina Grande", "CONTABILIDADE", "ASSISTENTE CONTÁBIL", "MÁRCIA C.", "5651", "contabilidade03@gamacaminhoes.com.br", "(83) 99135-0151"),
                ("Campina Grande", "CRM / AGENDAMENTO", "CRM", "SAMYRA", "-", "agendamento@grupogama.com.br", "(79) 99814-3486"),
                ("Campina Grande", "CRM / AGENDAMENTO", "AGENDAMENTO CRM", "FABRICIA", "4521", "agendamentocg@gamacaminhoes.com.br", "(83) 99626-9219"),
                ("Campina Grande", "CRM / AGENDAMENTO", "TELE PEÇAS", "FELIPE BARBOSA", "4517", "televendas@gamacaminhoes.com.br", "(83) 99937-0026"),
                ("Campina Grande", "FINANCEIRO", "CAIXA", "FABIANA", "4500", "financeiro@gamacaminhoes.com.br", "(83) 99156-1706"),
                ("Campina Grande", "MOTORISTA", "MOTORISTA", "FABIO", "-", "-", "(83) 99143-9364"),
                ("Campina Grande", "VEICULOS NOVOS", "GERENTE DE VENDAS", "HUMBERTO SOBRAL", "4516", "gvcg@gamacaminhoes.com.br", "(83) 98877-0259"),
                ("Campina Grande", "VEICULOS NOVOS", "RECEPÇÃO VENDAS", "CAROLINA", "4513", "assistentevendas@gamacaminhoes.com.br", "(83) 99837-0011"),
                ("Campina Grande", "VEICULOS NOVOS", "ASSISTENTE DE VENDAS", "JOSÉLIA", "4515", "vendas@gamacaminhoes.com.br", "(83) 98844-6965"),
                ("Campina Grande", "VEICULOS NOVOS", "VENDEDOR", "HUGO", "227", "hugo@gamacaminhoes.com.br", "(83) 99151-9301"),
                ("Campina Grande", "VEICULOS NOVOS", "VENDEDOR", "GENALDO", "-", "genaldo@gamacaminhoes.com.br", "(83) 99609-5253"),
                ("Campina Grande", "VEICULOS NOVOS", "VENDEDOR", "WILLIAMS", "-", "williams@gamacaminhoes.com.br", "(83) 98844-5098"),
                ("Campina Grande", "VEICULOS NOVOS", "ENTREGADOR TÉCNICO", "DIMITRI", "229", "vendas2cg@gamacaminhoes.com.br", "(83) 99914-0036"),
                ("Campina Grande", "VEICULOS NOVOS", "PROF DRIVE", "PROF DRIVE", "-", "profdrive@gamacaminhoes.com.br", "(83) 99699-0019"),
                ("Campina Grande", "VEICULOS NOVOS", "VOLKSCARE CG – APM", "MAURÍCIO", "-", "volkscare.cg@gamacaminhoes.com.br", "(83) 98844-6972"),
                ("Campina Grande", "ASSISTÊNCIA TÉCNICA", "GERENTE DE PÓS VENDA", "-", "4511", "at2@gamacaminhoes.com.br", "(83) 98844-6974"),
                ("Campina Grande", "ASSISTÊNCIA TÉCNICA", "ASSISTENTE RECEPÇÃO", "MARIANNA", "4510", "atcg@gamacaminhoes.com.br", "(83) 98844-6967"),
                ("Campina Grande", "ASSISTÊNCIA TÉCNICA", "ASSISTENTE RECEPÇÃO", "ANGÉLICA", "4510", "atcg@gamacaminhoes.com.br", "(83) 98844-6967"),
                ("Campina Grande", "ASSISTÊNCIA TÉCNICA", "ASSISTENTE ADM", "IVILY", "4520", "atcg2@gamacaminhoes.com.br", "(83) 99679-0134"),
                ("Campina Grande", "ASSISTÊNCIA TÉCNICA", "CHEFE DE OFICINA", "MARCELO", "-", "cocg@gamacaminhoes.com.br", "(83) 99699-0010"),
                ("Campina Grande", "ASSISTÊNCIA TÉCNICA", "CONSULTOR TÉCNICO", "NYELSON", "4503", "at@gamacaminhoes.com.br", "(83) 99807-0135"),
                ("Campina Grande", "ASSISTÊNCIA TÉCNICA", "CHAMEVOLKS", "MECANICOS", "-", "-", "(83) 99126-2294"),
                ("Campina Grande", "ASSISTÊNCIA TÉCNICA", "GARANTIA", "LINDAYANE", "-", "garantia@gamacaminhoes.com.br", "(83) 99679-0090"),
                ("Campina Grande", "ACESSORIOS / PECAS", "GERENTE DE PEÇAS", "CARLOS ANDRÉ", "4509", "pecas@gamacaminhoes.com.br", "(83) 98877-0262"),
                ("Campina Grande", "ACESSORIOS / PECAS", "VENDEDOR PEÇAS", "MARCOS", "4505", "pecas02.cg@gamacaminhoes.com.br", "(83) 98844-6970"),
                ("Campina Grande", "ACESSORIOS / PECAS", "VENDEDOR PEÇAS", "RAFAEL", "4507", "pecas01.cg@gamacaminhoes.com.br", "(83) 99157-9736"),
                ("Campina Grande", "ACESSORIOS / PECAS", "VENDEDOR PNEUS", "MICHELLE", "4506", "pneus1@gamacaminhoes.com.br", "(83) 99609-5432"),
                ("Campina Grande", "ACESSORIOS / PECAS", "SUPERVISOR ESTOQUE", "CLAUDIO", "4514", "supervisao01.cg@gamacaminhoes.com.br", "(83) 98844-6968"),
                ("Campina Grande", "ACESSORIOS / PECAS", "ASSIST. ADM", "LAIS", "4514", "estoque.cg@gamacaminhoes.com.br", "(83) 99837-0012"),
                ("Campina Grande", "ACESSORIOS / PECAS", "FERRAMENTARIA", "ILKINSON", "4523", "estoque2@gamacaminhoes.com.br", "(83) 99807-0410"),
                ("Campina Grande", "ACESSORIOS / PECAS", "ESTOQUISTA", "DIEGO", "4514", "estoque2@gamacaminhoes.com.br", "(83) 99679-0147"),
                ("Campina Grande", "ACESSORIOS / PECAS", "ESTOQUISTA", "IVANILDO", "4514", "estoque2@gamacaminhoes.com.br", "(83) 99679-0147"),

                # JOÃO PESSOA
                ("João Pessoa", "FINANCEIRO", "CAIXA", "MAIZA", "5653", "cpagar@gamacaminhoes.com.br", "(83) 98877-0264"),
                ("João Pessoa", "MOTORISTA", "MOTORISTA", "MOISÉS", "-", "-", "(83) 98802-5674"),
                ("João Pessoa", "VEICULOS NOVOS", "SUPERVISOR", "-", "-", "svjp@gamacaminhoes.com.br", "(83) 99837-0013"),
                ("João Pessoa", "VEICULOS NOVOS", "VOLKSCARE JP – APM", "RAFAEL", "-", "volkscare.jp@gamacaminhoes.com.br", "(83) 98849-1567"),
                ("João Pessoa", "VEICULOS NOVOS", "VENDEDOR", "PAULO HENRIQUE", "5652", "paulo@gamacaminhoes.com.br", "(83) 99609-5200"),
                ("João Pessoa", "VEICULOS NOVOS", "ASSISTENTE VENDAS", "SANDRA", "5666", "vendas3jp@gamacaminhoes.com.br", "(83) 98844-6973"),
                ("João Pessoa", "VEICULOS NOVOS", "ASSISTENTE VENDAS", "LUCAS", "5672", "vendas2jp@gamacaminhoes.com.br", "(83) 99837-0001"),
                ("João Pessoa", "VEICULOS NOVOS", "ASSISTENTE VENDAS", "ABRAHÃO", "5672", "vendas2jp@gamacaminhoes.com.br", "(83) 99837-0001"),
                ("João Pessoa", "VEICULOS NOVOS", "VENDEDOR", "CLEDSON", "5652", "cledson@gamacaminhoes.com.br", "(83) 98844-5097"),
                ("João Pessoa", "VEICULOS NOVOS", "VENDEDOR", "PAULO GABRIEL", "5652", "paulo.gabriel@gamacaminhoes.com.br", "(83) 98758-7680"),
                ("João Pessoa", "ASSISTÊNCIA TÉCNICA", "GERENTE", "HUMBERTO", "5661", "at.jp@gamacaminhoes.com.br", "(83) 98844-6975"),
                ("João Pessoa", "ASSISTÊNCIA TÉCNICA", "ASSISTENTE ADM", "ALESSANDRA", "5667", "at.jp2@gamacaminhoes.com.br", "(83) 98877-0260"),
                ("João Pessoa", "ASSISTÊNCIA TÉCNICA", "CHAMEVOLKS", "MECANICOS", "-", "-", "(83) 98802-5673"),
                ("João Pessoa", "ASSISTÊNCIA TÉCNICA", "GARANTIA", "JUAN", "5657", "auxgarantia@gamacaminhoes.com.br", "(83) 99819-1555"),
                ("João Pessoa", "ASSISTÊNCIA TÉCNICA", "CONSULTOR(A) TÉCNICO", "JULIENDY", "5659", "at1.jp@gamacaminhoes.com.br", "(83) 99609-5400"),
                ("João Pessoa", "ASSISTÊNCIA TÉCNICA", "CONSULTORA TÉCNICA", "TATIANE", "5660", "at2.jp@gamacaminhoes.com.br", "(83) 99175-8900"),
                ("João Pessoa", "ASSISTÊNCIA TÉCNICA", "OFICINA", "MECANICOS", "5673", "-", "-"),
                ("João Pessoa", "ACESSORIOS / PECAS", "VENDOR DE PEÇAS", "BRUNO", "5665", "pecas.jp@gamacaminhoes.com.br", "(83) 98844-6966"),
                ("João Pessoa", "ACESSORIOS / PECAS", "VENDOR DE PEÇAS", "ESTEFANIA", "5664", "pecas01.jp@gamacaminhoes.com.br", "(83) 99807-0290"),
                ("João Pessoa", "ACESSORIOS / PECAS", "ASSISTENTE ADM", "JULIANA", "-", "pecas03.jp@gamacaminhoes.com.br", "(83) 99807-0390"),
                ("João Pessoa", "ACESSORIOS / PECAS", "FERRAMENTARIA", "RONALDO", "5656", "estoque.jp@gamacaminhoes.com.br", "(83) 99807-0119"),
                ("João Pessoa", "ACESSORIOS / PECAS", "ESTOQUISTA", "PEDRO MANUEL", "5655", "estoque2.jp@gamacaminhoes.com.br", "(83) 99679-0146"),
                ("João Pessoa", "ACESSORIOS / PECAS", "ESTOQUISTA", "YAGO", "5655", "estoque2.jp@gamacaminhoes.com.br", "(83) 99679-0146")
            ]
            for u, s, c, n, ext, em, cel in dados_iniciais:
                ext_obj = CompanyExtension(
                    unit=u,
                    sector=s,
                    role_name=c,
                    name=n,
                    extension=ext,
                    email=em,
                    phone=cel
                )
                db.session.add(ext_obj)
            db.session.commit()
            print("[INFO] Lista inicial de ramais carregada com sucesso!")
    except Exception as e:
        db.session.rollback()
        print(f"[AVISO] Falha ao inicializar ramais: {e}")

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
                    ('is_hr', 'BOOLEAN DEFAULT FALSE'),
                    ('last_announcement_view', 'TIMESTAMP'),
                    ('failed_login_attempts', 'INTEGER DEFAULT 0'),
                    ('locked_until', 'TIMESTAMP'),
                    ('last_login_ip', 'VARCHAR(50)'),
                    ('last_user_agent', 'VARCHAR(255)')
                ]
                
                for col_name, col_type in columns_to_ensure:
                    if col_name not in cols:
                        try:
                            with db.engine.begin() as conn:
                                print(f"[MIGRATION] Adicionando coluna {col_name} na tabela {table_ref}...")
                                conn.execute(text(f"ALTER TABLE {table_ref} ADD COLUMN {col_name} {col_type}"))
                        except Exception as ex:
                            print(f"[MIGRATION EXCEPTION] Coluna {col_name}: {ex}")

            # Migração: colunas em saved_password
            if 'saved_password' in tables:
                sp_cols = [c['name'] for c in inspector.get_columns('saved_password')]
                is_postgres = 'postgres' in db.engine.url.drivername or 'postgresql' in str(db.engine.url)
                sp_ref = '"saved_password"' if is_postgres else 'saved_password'
                if 'created_at' not in sp_cols:
                    try:
                        with db.engine.begin() as conn:
                            print("[MIGRATION] Adicionando coluna created_at em saved_password...")
                            ts_clause = "DEFAULT CURRENT_TIMESTAMP" if is_postgres else ""
                            conn.execute(text(f"ALTER TABLE {sp_ref} ADD COLUMN created_at TIMESTAMP {ts_clause}"))
                    except Exception as ex:
                        print(f"[MIGRATION EXCEPTION] saved_password.created_at: {ex}")
                if 'encrypted_notes' not in sp_cols:
                    try:
                        with db.engine.begin() as conn:
                            print("[MIGRATION] Adicionando coluna encrypted_notes em saved_password...")
                            notes_type = 'BYTEA' if is_postgres else 'BLOB'
                            conn.execute(text(f"ALTER TABLE {sp_ref} ADD COLUMN encrypted_notes {notes_type}"))
                    except Exception as ex:
                        print(f"[MIGRATION EXCEPTION] saved_password.encrypted_notes: {ex}")

            # Migração: colunas em announcement
            if 'announcement' in tables:
                ann_cols = [c['name'] for c in inspector.get_columns('announcement')]
                is_postgres = 'postgres' in db.engine.url.drivername or 'postgresql' in str(db.engine.url)
                ann_ref = '"announcement"' if is_postgres else 'announcement'
                if 'document_link' not in ann_cols:
                    try:
                        with db.engine.begin() as conn:
                            print("[MIGRATION] Adicionando coluna document_link em announcement...")
                            conn.execute(text(f"ALTER TABLE {ann_ref} ADD COLUMN document_link VARCHAR(500)"))
                    except Exception as ex:
                        print(f"[MIGRATION EXCEPTION] announcement.document_link: {ex}")
                if 'target_unit' not in ann_cols:
                    try:
                        with db.engine.begin() as conn:
                            print("[MIGRATION] Adicionando coluna target_unit em announcement...")
                            conn.execute(text(f"ALTER TABLE {ann_ref} ADD COLUMN target_unit VARCHAR(50) DEFAULT 'Todas'"))
                    except Exception as ex:
                        print(f"[MIGRATION EXCEPTION] announcement.target_unit: {ex}")
                if 'is_urgent' not in ann_cols:
                    try:
                        with db.engine.begin() as conn:
                            print("[MIGRATION] Adicionando coluna is_urgent em announcement...")
                            conn.execute(text(f"ALTER TABLE {ann_ref} ADD COLUMN is_urgent BOOLEAN DEFAULT FALSE"))
                    except Exception as ex:
                        print(f"[MIGRATION EXCEPTION] announcement.is_urgent: {ex}")
                if 'publish_at' not in ann_cols:
                    try:
                        with db.engine.begin() as conn:
                            print("[MIGRATION] Adicionando coluna publish_at em announcement...")
                            pub_clause = "DEFAULT CURRENT_TIMESTAMP" if is_postgres else ""
                            conn.execute(text(f"ALTER TABLE {ann_ref} ADD COLUMN publish_at TIMESTAMP {pub_clause}"))
                    except Exception as ex:
                        print(f"[MIGRATION EXCEPTION] announcement.publish_at: {ex}")
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

# Inicializa o banco (Roda no gunicorn com segurança)
try:
    with app.app_context():
        inicializar_banco()
except Exception as e:
    print(f"[ERRO CRÍTICO NA INICIALIZAÇÃO DO BANCO]: {e}")

if __name__ == '__main__':
    porta = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=porta, debug=False)
