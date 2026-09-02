# 🔐 GAMAPASS — Plataforma Corporativa de Credenciais, Mural & Ramais

> **Sistema Web Corporativo de Alta Segurança da Gama Caminhões & Ônibus para Gestão Centralizada de Senhas, Compartilhamento Seguro entre Membros, Mural de Comunicados do RH e Lista Telefônica Integrada.**

---

## 🌟 Visão Geral

O **GAMAPASS** é a plataforma oficial da **Gama Caminhões** desenvolvida para elevar os padrões de segurança da informação da empresa, eliminando práticas de risco — como senhas anotadas em papéis, compartilhamento de credenciais por WhatsApp e esquecimento de acessos a sistemas críticos (*Syonet CRM/ERP, Portal Volkswagen, Portais de Peças, E-mails corporativos, etc.*).

A plataforma conta com uma interface dividida em **3 Abas Principais**:
1. 🔐 **Cofre de Senhas:** Armazenamento seguro criptografado com AES-128, notas confidenciais ocultas, gerador de senhas e compartilhamento direto entre colaboradores.
2. 📢 **Mural & Comunicados:** Avisos oficiais do RH com direcionamento por filial (*Campina Grande*, *João Pessoa* ou *Todas*), destaque para comunicados urgentes e repositório de arquivos e formulários para download.
3. 📞 **Lista de Ramais:** Guia telefônico completo com busca instantânea, instruções de telefonia PABX (`FLASH + RAMAL`), gestão em tempo real pelo RH e exportação em documento **PDF**.

---

## 🚀 Principais Funcionalidades

### 1. 🔐 Cofre de Senhas Criptografado & Notas Seguras
- **Criptografia Militar:** Todas as senhas e notas livres confidenciais são criptografadas em repouso com **AES-128 em modo CBC (Fernet)**.
- **Design Moderno dos Cards:**
  - Botões dedicados **`Ver`** e **`Copiar`** em azul sólido acima da linha de ações.
  - Linha de rodapé com ações rápidas: `Editar | Apagar | Histórico`.
  - Botão **`Compartilhar`** posicionado abaixo da divisória para fácil acesso.
- **Notas Seguras Ocultas:** Anotações com PINs, ramais e dicas de acesso ficam ocultas por padrão, com botão `[+] Ver Nota Segura` / `[-] Ocultar Nota Segura`.
- **Validação de Força & Gerador de Senhas:** Indicador visual de complexidade e gerador de senhas aleatórias seguras com 1 clique.

### 2. 🤝 Compartilhamento Seguro entre Colaboradores
- Compartilhe o acesso a qualquer serviço corporativo digitando apenas o login do colega (ex: `claudio.pecas`).
- Seção destacada em verde-menta **`Credenciais Compartilhadas Comigo`** no painel do destinatário.
- **Notificação Automática:** O colega é avisado via sino e notificação de que recebeu uma credencial ou que ela foi alterada pelo proprietário.
- **Revogação Instantânea:** O proprietário pode revogar o acesso a qualquer momento.

### 3. 📥 Importador Universal de Senhas (CSV)
- Compatibilidade total com arquivos exportados de:
  - 🦊 **Mozilla Firefox** (com tratamento automático de timestamps e URLs)
  - 🌐 **Google Chrome, Microsoft Edge, Brave, Opera e Vivaldi**
  - 🍎 **Safari / Senhas do macOS e iOS**
  - 🛡️ **Bitwarden, 1Password, LastPass e Dashlane**
  - 📄 **GAMAPASS Nativo (CSV)**
- Tela de revisão com seleção de registros, edição de nomes de serviços e descarte de senhas indesejadas antes de salvar.

### 4. 📢 Mural & Central de Arquivos do RH
- **Visual em 2 Colunas:**
  - **Coluna Esquerda (Central de Notificações & Mural):** Comunicados oficiais do RH, com destaque em borda vermelha e badge `URGENTE` para avisos prioritários.
  - **Coluna Direita (Mural de Arquivos do RH):** Download imediato de formulários, manuais e anexos em PDF/imagens com badges por filial, além de atalho direto para a pasta corporativa do Google Drive.
- **Agendamento Futuro:** O RH pode programar data e horário para comunicados entrarem no ar automaticamente.

### 5. 📞 Lista de Ramais Oficial & Gestão pelo RH
- **Tabela Interativa:** Contatos oficiais das unidades **Campina Grande** e **João Pessoa** com nome, setor, cargo, ramal, e-mail e celular.
- **Instruções PABX Integradas:**
  - Transferir ligação: `FLASH + NÚMERO DO RAMAL`
  - Retornar se ocupado: `FLASH + # + 0`
  - Atender ramal específico: `# + 5 NÚMERO RAMAL + *`
  - Atender qualquer ramal: `FLASH + 22`
- **Gestão pelo RH / TI:** Botão `➕ Adicionar Contato`, além de edição e exclusão inline de qualquer registro.
- **Exportação em PDF:** Botão `📄 Exportar PDF` gera relatório oficial formatado para impressão via ReportLab.

### 6. 🔔 Notificações Padronizadas do Sino & Som Nativo
- O sino no topo da tela notifica instantaneamente sem recarregar a página (`polling` a cada 8 segundos), exibindo exclusivamente as 4 mensagens padronizadas do sistema:
  1. *"Um novo aviso foi adicionado por NOME_DA_PESSOA."*
  2. *"Um novo aviso foi adicionado por NOME_DA_PESSOA e tem caráter urgente."*
  3. *"Uma nova senha foi compartilhada com você, atualize a página para ter acesso."*
  4. *"Uma credencial compartilhada com você foi alterada por NOME_DA_PESSOA, atualize a página para ter acesso."*
- **Sino Suave Nativo:** Alerta sonoro sintetizado em alta definição no navegador via *Web Audio API*.

### 7. 🛡️ Segurança de TI, Auditoria & Detecção de IP Local
- **IP Interno da Empresa (`10.5.0.XX`):** Detecção automática do IP local corporativo via WebRTC no navegador, evitando falsos alertas por IP externo de provedor.
- **Proteção Anti-Brute Force:** Bloqueio automático de contas após **5 tentativas consecutivas de senha incorreta** (15 minutos).
- **Alerta de Novo Dispositivo/IP:** Envio automático de e-mail ao titular caso ocorra login em máquina ou navegador diferente.
- **Relatório de Auditoria:** Painel de auditoria com filtros combinados (datas, filiais, departamentos, ações) e exportação em CSV compatível com Excel em português.

---

## 🏗️ Arquitetura Tecnológica

| Camada | Tecnologias Utilizadas |
| :--- | :--- |
| **Backend** | Python 3.11+, Flask, Flask-SQLAlchemy, Flask-Login, Werkzeug |
| **Segurança & Criptografia** | Cryptography (Fernet AES-128 CBC), scrypt (Password Hashing) |
| **Geração de Relatórios** | ReportLab (Geração de PDFs Oficiais) |
| **Banco de Dados** | PostgreSQL (Neon.tech / Nuvem) e SQLite (Fallback Local) |
| **Frontend** | HTML5, CSS3 Custom Theme (Gama Navy/Gold/VW), Vanilla JavaScript, Chart.js, Web Audio API, WebRTC |
| **Serviço de E-mails** | Brevo API, Resend API e SMTP Corporativo TLS |
| **Deploy & Nuvem** | Render.com (Gunicorn WSGI) |

---

## 🗄️ Esquema do Banco de Dados

```text
user (Usuários e Perfis de Acesso)
 ├── saved_password (Cofre Pessoal Criptografado)
 │    └── shared_password (Compartilhamento entre Membros)
 ├── password_history (Histórico de Alterações de Senhas)
 ├── announcement (Mural de Comunicados do RH)
 │    ├── announcement_file (Anexos e Documentos)
 │    └── announcement_view (Registro de Leituras por Usuário)
 ├── company_extension (Lista Oficial de Ramais e Telefonia)
 ├── user_notification (Central de Alertas em Tempo Real)
 └── audit_log (Log Global de Auditoria e Segurança)
```

---

## 📋 Como Utilizar o Sistema (Guia Rápido do Colaborador)

### 1️⃣ Primeiro Acesso
1. Acesse o link oficial enviado pelo TI: `https://gamapass.onrender.com`
2. Digite seu usuário corporativo e a senha provisória recebida por e-mail.
3. Defina sua nova senha pessoal de acesso e confirme seu nome completo.

### 2️⃣ Utilizando o Cofre de Senhas
- **Adicionar Senha:** Clique em **`[+] Nova Senha`**, preencha o serviço (ex: *Syonet*), login e senha (ou use o botão *🎲 Gerar Senha*).
- **Ver ou Copiar:** No cartão do serviço, clique no botão azul **`Ver`** para revelar a senha ou **`Copiar`** para enviar à área de transferência.
- **Notas Seguras:** Clique em **`[+] Ver Nota Segura`** para ler dados confidenciais anotados.
- **Compartilhar:** Clique em **`Compartilhar`**, digite o login do colega e clique em *Enviar Acesso*.

### 3️⃣ Consultando o Mural do RH
- Acesse a aba **📢 Mural & Comunicados** para ler os avisos e notícias da empresa.
- Na coluna direita, clique em **`Baixar`** para baixar formulários e manuais do RH ou acesse a pasta do Google Drive.

### 4️⃣ Consultando a Lista de Ramais
- Acesse a aba **📞 Lista de Ramais** para localizar qualquer colega por nome, setor ou função.
- Utilize a busca instantânea ou os filtros de filial (*Campina Grande / João Pessoa*).
- Clique em **`📄 Exportar PDF`** para baixar o guia telefônico oficial para impressão.
