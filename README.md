# 🔐 GAMAPASS — Gerenciador Corporativo Seguro de Credenciais & Mural de Avisos

> **Plataforma Web Corporativa de Alta Segurança para Gestão Centralizada de Senhas, Compartilhamento Seguro entre Membros, Mural de Comunicados do RH e Auditoria de TI.**

---

## 🌟 Visão Geral

O **GAMAPASS** é a plataforma oficial da **Gama Caminhões** desenvolvida para eliminar vulnerabilidades críticas de segurança da informação — como o uso de senhas anotadas em papéis, compartilhamento de credenciais confidenciais por WhatsApp e esquecimento de senhas de portais de treinamento, montadoras e sistemas de gestão (*Syonet, Volkswagen, Portais de Peças, E-mails corporativos, etc.*).

Além do cofre pessoal de senhas criptografadas, o sistema integra uma **Central de Comunicados e Arquivos do RH**, **Auditoria de TI com Filtros Avançados**, **Gráficos Gerenciais de Segurança**, **Sincronização em Tempo Real** e **Avisos Sonoros Personalizados**.

---

## 🚀 Principais Funcionalidades

### 1. 🛡️ Cofre de Senhas Criptografado & Notas Seguras
- **Criptografia Militar:** Todas as senhas e anotações livres são criptografadas no banco de dados com **AES-128 em modo CBC via Fernet**.
- **Notas Livres Seguras:** Armazenamento de PINs, perguntas de segurança, ramais e instruções confidenciais em cada registro.
- **Validação de Força de Senha:** Feedback visual instantâneo na criação de senhas fortes.
- **Gerador Automático de Senhas:** Criação de senhas aleatórias de alta complexidade com 1 clique.

### 2. 🤝 Compartilhamento Seguro entre Membros
- Compartilhe o acesso a qualquer serviço corporativo digitando apenas o login do colega (ex: `marcos.silva`).
- Aba dedicada **"🤝 Credenciais Compartilhadas Comigo"** no painel do destinatário.
- Notificação instantânea ao receber compartilhamentos e alerta automático quando o proprietário atualizar a senha.
- Revogação de acesso imediata a qualquer momento pelo proprietário.

### 3. 📥 Importador Universal de Senhas (CSV)
- **Compatibilidade Total:** Importa arquivos de senhas exportados de qualquer navegador ou gerenciador:
  - 🦊 **Mozilla Firefox** (com correção de timestamps e extração de domínio)
  - 🌐 **Google Chrome, Microsoft Edge, Brave, Opera e Vivaldi**
  - 🍎 **Safari / Senhas do macOS e iOS**
  - 🛡️ **Bitwarden, 1Password, LastPass, Dashlane e KeePass**
  - 📄 **GAMAPASS Nativo** (delimitadores `;` ou `,`)
- **Tela de Revisão Inteligente:** Sugestão automática de nomes de serviços a partir da URL, campos editáveis, visualizador de senhas (`👁️`) e botão para descartar registros indesejados.

### 4. 📢 Mural de Avisos & Mural de Arquivos do RH
- **Direcionamento por Unidade:** O RH pode publicar avisos para **Campina Grande**, **João Pessoa** ou **Todas as Unidades**.
- **Agendamento Futuro:** Programação de data/hora para entrada automática de comunicados no ar.
- **Avisos Urgentes:** Destaque visual com borda vermelha e fixação prioritária no topo.
- **Mural de Arquivos:** Download de comunicados e formulários em PDF/imagens sem exibir extensão nos nomes.
- **Rastreabilidade de Leituras:** Controle de quais colaboradores já visualizaram cada comunicado.

### 5. 🔔 Notificações em Tempo Real & 🔊 Aviso Sonoro
- Monitoramento em tempo real (polling leve via Web API a cada 8 segundos) sem necessidade de recarregar a página (`F5`).
- **5 Opções de Efeitos Sonoros** (sintetizados nativamente via *Web Audio API*):
  1. 🔔 *Sino / Chime Suave (Padrão)*
  2. 🎵 *Ding-Dong Moderno*
  3. ⚡ *Pop Discreto (Curto)*
  4. 🎺 *Tríade Positiva (Alegre)*
  5. 🔕 *Silencioso (Mudo)*
- Botão **`▶ Testar`** no menu suspenso para pré-escuta e salvamento no navegador.

### 6. 📊 Painel Administrativo de TI & Métricas (Chart.js)
- **Gráfico de Distribuição por Filial:** Proporção de usuários em Campina Grande vs João Pessoa vs Outros.
- **Gráfico de Saúde das Senhas:** Auditoria de senhas fracas, médias e fortes em toda a empresa.
- **Taxa de Adesão da Equipe (%):** Acompanhamento de colaboradores com primeiro acesso concluído.
- **Proteção Anti-Brute Force:** Bloqueio automático de contas após **5 tentativas erradas** (15 minutos) com botão de desbloqueio imediato pelo TI.
- **Alerta de Novo IP/Dispositivo:** Disparo automático de e-mail ao usuário caso haja login de local incomum.

### 7. 📋 Relatórios & Auditoria com Filtros Avançados
- Rastreamento imutável de todas as ações (`LOGIN`, `SENHA_CRIADA`, `SENHA_EDITADA`, `COMPARTILHAMENTO`, etc.).
- Filtros combinados por **Período (Data Início e Fim)**, **Unidade/Filial**, **Departamento**, **Usuário** e **Tipo de Ação**.
- **Exportação para Planilha CSV** formatada com BOM UTF-8 e delimitador `;` para compatibilidade total com o Microsoft Excel em português.

---

## 🏗️ Arquitetura Tecnológica

| Camada | Tecnologias Utilizadas |
| :--- | :--- |
| **Backend** | Python 3.11+, Flask, Flask-SQLAlchemy, Flask-Login, Werkzeug |
| **Segurança & Criptografia** | Cryptography (Fernet AES-128 CBC), scrypt (Password Hashing) |
| **Banco de Dados** | PostgreSQL (Nuvem / Neon.tech) e SQLite (Fallback Local) |
| **Frontend** | HTML5, CSS3 Custom Theme (Gama Navy/Gold/VW), Vanilla JavaScript, Chart.js, Web Audio API, WebRTC |
| **Serviço de E-mails** | Brevo API, Resend API e SMTP Corporativo TLS |
| **Deploy & Nuvem** | Render.com (Gunicorn WSGI) + Neon.tech (PostgreSQL Serverless) |

---

## 🗄️ Esquema do Banco de Dados

O banco de dados é composto por 9 entidades relacionais:

```text
user (Usuários e Perfis)
 ├── saved_password (Cofre Pessoal Criptografado)
 │    └── shared_password (Compartilhamento entre Membros)
 ├── password_history (Histórico de Alterações de Senhas)
 ├── announcement (Mural de Comunicados do RH)
 │    ├── announcement_file (Anexos e Documentos)
 │    └── announcement_view (Registro de Leituras por Usuário)
 ├── user_notification (Central de Alertas em Tempo Real)
 └── audit_log (Log Global de Auditoria e Segurança)
```

---

## ⚙️ Variáveis de Ambiente

Configure as variáveis abaixo no painel de hospedagem (ex: Render):

```env
# Banco de Dados
DATABASE_URL=postgresql://usuario:senha@ep-xyz.region.aws.neon.tech/neondb?sslmode=require

# Chaves de Segurança
SECRET_KEY=sua_chave_secreta_de_sessao_longa
ENCRYPTION_KEY=chave_fernet_32_bytes_base64_url_safe

# Primeiro Administrador
INITIAL_ADMIN_USER=admin
INITIAL_ADMIN_PASS=SenhaAdminForte@123

# Envio de E-mails (Brevo API ou Resend API)
BREVO_API_KEY=xkeysib-sua-chave-aqui
RESEND_API_KEY=re_sua-chave-aqui
EMAIL_REMETENTE=seu-email@gmail.com
```

---

## 👥 Guia do Colaborador (Primeiro Acesso)

1. **Acesso:** Acesse o link oficial do GAMAPASS enviado pelo TI.
2. **Login Inicial:** Digite seu usuário e a senha provisória informada no e-mail de convite.
3. **Configuração Obrigatória:**
   - Defina sua senha definitiva forte (com letras maiúsculas, minúsculas, números e caracteres especiais).
   - Confirme seu nome completo, e-mail corporativo, filial e setor.
4. **Pronto!** Seu cofre seguro estará liberado para guardar suas senhas e receber comunicados oficiais da empresa.

---

## 📄 Licença & Direitos

Desenvolvido para **Gama Caminhões** — Todos os direitos reservados.
