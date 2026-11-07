[English](../en/ROADMAP.md) | **Português (Brasil)**

# Roadmap

## MVP implementado

- interpretação e normalização de referências `secret://`
- vault local cifrado com AES-GCM
- CLI administrativa de segredos e políticas
- API administrativa FastAPI sem endpoints de leitura de valores
- motor que avalia a política antes da resolução
- substituição aninhada e mascaramento por valor exato
- auditoria em SQLite só com metadados
- perfis de sessão só com referências
- validação de referências em `.env`
- `interpose run` independente de agente
- lista de permissão do ambiente e remoção de credenciais herdadas
- broker HTTP de encaminhamento e reverso
- transporte local explícito `/proxy/{host}` com HTTPS iniciado pelo broker
- políticas com esquema e padrões externos seguros
- vínculos de ambiente públicos e de credencial separados
- substituição em query e formulário URL-encoded
- substituição em JSON, headers e corpo
- rejeição explícita de HTTPS `CONNECT`, que não é suportado
- modo de compatibilidade limitado `interpose-exec`
- slots de injeção, lista de caminhos permitidos e `allow_exec` explícito nas políticas
- escopos de projeto e global para segredos e políticas
- `interpose up` com painel de configuração local
- serviço do Windows como `NT SERVICE\Interpose`: runtime próprio em Program Files, vault protegido
  por ACL, `interpose setup` executado uma vez
- roteamento do broker por projeto (`/p/{projeto}/proxy/...`) e `${INTERPOSE_PROXY}` nos perfis

## V2: Isolamento aplicado

- ~~daemon confiável com identidade própria no sistema operacional~~ — feito no Windows; Linux
  (systemd `DynamicUser=`) e macOS (launchd) em seguida
- ~~ACLs no sistema de arquivos para o vault e a chave mestra~~ — feito no Windows
- presença do usuário (Windows Hello, Touch ID, polkit) para abrir uma sessão no painel
- Named Pipe autenticado no Windows
- socket Unix autenticado no Linux e no macOS
- namespaces no Linux e controle de saída com nftables
- integração com Windows Filtering Platform e AppContainer
- suporte a Network Extension e sandbox no macOS
- controles de DNS e QUIC
- terminação TLS confiável com CA por sessão
- controles de política para redirecionamento, DNS rebinding, caminho e faixa de IP

## V3: Cofres de segredos

- HashiCorp Vault
- Azure Key Vault
- AWS Secrets Manager
- GCP Secret Manager
- Gerenciador de Credenciais do Windows
- Keychain do macOS
- Secret Service do Linux

## V4: Brokers de protocolo

- proxy de autenticação de banco de dados
- agente de assinatura SSH
- broker de assinatura AWS SigV4
- serviço genérico de assinatura HMAC e assimétrica
- conexões mTLS iniciadas pelo broker
- assinatura de certificados
- credenciais dinâmicas e de curta duração

## V5: Integrações com agentes

- geração de `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` e regras do Cursor
- adaptador de sessão para o Codex CLI
- adaptador de sessão para o Claude Code
- launcher para o Cursor
- adaptador de sessão para o Gemini CLI
- plano de controle MCP opcional, só para referências e capacidades
