# GAMAPASS - Gerenciador Seguro de Credenciais Corporativas

Sistema web para gestão segura e criptografada de credenciais e senhas corporativas para funcionários da empresa.

---

## 🚀 Como Hospedar Gratuitamente na Nuvem (Render + Neon)

A combinação mais recomendada e 100% gratuita é:
1. **Neon.tech** (Banco de Dados PostgreSQL gratuito para sempre, seguro e na nuvem).
2. **Render.com** (Hospedagem Web gratuita da aplicação Flask com HTTPS automático).

---

### Passo 1: Criar o Banco de Dados Gratuito (Neon.tech)
1. Acesse [neon.tech](https://neon.tech) e crie uma conta gratuita.
2. Crie um novo projeto (ex: `gamapass-db`).
3. Copie a **Connection String** (URL de conexão Postgres).
   - Ela tem o formato: `postgresql://usuario:senha@ep-xyz.region.aws.neon.tech/neondb?sslmode=require`

---

### Passo 2: Subir o Código para o GitHub
1. Crie um repositório no seu GitHub (pode ser **Privado** para segurança da sua empresa).
2. Na pasta do projeto (`PassWallet`), inicialize o Git e envie os arquivos:
   ```bash
   git init
   git add .
   git commit -m "Versão pronta para produção GAMAPASS"
   git branch -M main
   git remote add origin https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
   git push -u origin main
   ```

---

### Passo 3: Hospedar no Render (Render.com)
1. Acesse [render.com](https://render.com) e conecte sua conta do GitHub.
2. Clique em **New +** -> **Web Service**.
3. Selecione o repositório do GAMAPASS.
4. Preencha as configurações:
   - **Name:** `gamapass` (ou o nome da sua empresa)
   - **Language:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Instance Type:** `Free`
5. Vá na seção **Environment Variables** (Variáveis de Ambiente) e adicione:
   - `DATABASE_URL`: *(Cole a URL do Neon que você copiou no Passo 1)*
   - `SECRET_KEY`: *(Gere executando `python gerar_chaves.py` ou coloque uma senha longa)*
   - `ENCRYPTION_KEY`: *(Gere executando `python gerar_chaves.py`)*
   - `INITIAL_ADMIN_USER`: `admin` *(Login do primeiro acesso admin)*
   - `INITIAL_ADMIN_PASS`: `SuaSenhaAdminForte@123` *(Senha do primeiro acesso admin)*
6. Clique em **Create Web Service**.

Em poucos minutos, você terá um link seguro: `https://gamapass.onrender.com`.

---

## 👥 Como os Funcionários Vão Usar

1. **Acesso:** Você compartilha o link (ex: `https://gamapass.onrender.com`) com os funcionários.
2. **Primeiro Login:**
   - O Administrador cadastra os logins dos funcionários pelo **Painel Admin** com uma senha provisória padrão.
   - Ao acessar pela primeira vez, o funcionário é automaticamente redirecionado para a tela de **Primeiro Acesso** para:
     - Definir sua senha pessoal definitiva (com requisitos de segurança).
     - Preencher seu Nome Completo, E-mail, IP da Máquina, Departamento, Setor e Unidade.
3. **Uso Diário:**
   - Cada funcionário só visualiza e gerencia suas próprias credenciais.
   - Criptografia de ponta a ponta (Fernet AES).
   - Suporte a importação e exportação de senhas via planilha CSV.
   - Sistema de redefinição de senha com envio por e-mail institucional.
