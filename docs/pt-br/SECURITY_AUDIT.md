[English](../en/SECURITY_AUDIT.md) | **Português (Brasil)**

# Auditoria de segurança — novembro de 2026

Revisão adversarial do broker, do motor de políticas, do mascaramento, do painel, da
API de controle e do `interpose-exec`, feita antes da primeira versão pública. O
revisor partiu só do código, sem as conclusões dos autores, e tentou obter o valor de
um segredo ou fazer o broker enviá-lo a um host que o operador não aprovou.

**Modelo de atacante:** código arbitrário rodando como o mesmo usuário Windows não
elevado do agente. Ele lê qualquer arquivo que esse usuário lê, inicia processos e
envia qualquer requisição aos listeners do loopback.

Cada achado foi reproduzido contra um destino falso (nenhum segredo saiu da
máquina), e cada correção vem com um teste de regressão em
[`tests/test_audit_regressions.py`](../../tests/test_audit_regressions.py). Esses
testes falham no código de antes da correção.

## Achados

| # | Severidade | Achado | Situação |
|---|---|---|---|
| 1 | Crítica | Host da política e host da conexão podiam divergir no modo de proxy pelo header Host | Corrigido |
| 2 | Alta | Políticas de projeto não contêm um processo do mesmo usuário | Documentado: não é fronteira |
| 3 | Alta | O token de controle do serviço permite que um processo do mesmo usuário altere políticas | Corrigido: aprovação com Windows Hello para alterações que ampliam |
| 4 | Média | O mascaramento não pegava codificações comuns nem corpos comprimidos | Corrigido |
| 5 | Baixa | Hosts Unicode eram normalizados de forma diferente pela política e pelo cliente HTTP | Corrigido |

### 1. Host da política vs host da conexão (crítica, corrigido)

**Causa.** No modo de proxy pelo header `Host` (e na forma absoluta), o destino vinha
do header sem tratamento, e a política comparava esse texto com `fnmatch`. A URL de
saída era montada a partir do mesmo texto e reanalisada pelo cliente HTTP, que
encerra a autoridade no primeiro `/`, `?` ou `#`. Um valor que casava com um padrão
curinga como texto podia fazer o cliente conectar em outro host, e a credencial era
injetada numa requisição para o atacante. Políticas com host exato não eram
afetadas.

**Correção.**
- O header `Host` e os alvos em forma absoluta passam pelo mesmo analisador estrito
  do transporte `/proxy/{host}`. Ele aceita um único hostname ASCII ou IP e uma porta
  opcional. Recusa userinfo, caminho, query, fragmento, barra invertida, espaços e
  Unicode, que precisa vir como rótulo `xn--`.
- `verified_upstream_url` reanalisa a URL que o cliente vai discar. O host, a porta e
  o caminho precisam ser iguais aos aprovados pela política, e segmentos `.`/`..` são
  recusados. Tudo o que o cliente reescreveria é rejeitado em vez de adivinhado.
- Os padrões de permissão respeitam rótulos. Um padrão é um `host[:porta]` exato, um
  `*.example.com` no início, que cobre só subdomínios, ou `*`. Globs como `api.*` ou
  `*example.com` são recusados ao gravar a política, e uma política salva que viole
  essa regra agora nega em vez de casar. Padrões de negação mantêm a semântica de
  glob, porque casar mais ali só bloqueia mais.

### 2. Escopos de projeto não isolam (alta, documentado)

A rota de projeto (`/p/{id}/proxy/...`) escolhe quais políticas valem. O broker não
sabe qual processo está chamando, então código rodando como o usuário pode escolher
a rota de qualquer projeto, ou a global. Uma política de projeto mais restrita que a
global, portanto, não contém nada.

Nenhuma mudança de código resolve isso sem identidade por processo, que o HTTP no
loopback não oferece (veja o item de atribuição no [roadmap](ROADMAP.md)). Em vez
disso, o [modelo de ameaças](THREAT_MODEL.md) e a documentação do motor de políticas
agora dizem a garantia real: um segredo só alcança a união dos hosts permitidos pelas
suas políticas, de qualquer lugar da máquina. Escreva a política mais restrita no
escopo global.

### 3. Token de controle (alta, corrigido)

O `client\control.token` é legível pelo usuário que instalou, para que o
`interpose up` abra sessões do painel sem um segundo login. Um processo do mesmo
usuário podia usá-lo para abrir uma sessão e adicionar um host permitido, o que
anulava a política de saída de todos os segredos. Os valores continuavam sem poder
ser lidos.

**Correção: presença do usuário para alterações que ampliam.** Abrir uma sessão
continua sem segundo login. Toda alteração de política que possa mandar um segredo
para um lugar novo precisa de uma asserção WebAuthn do autenticador do operador:
Windows Hello, ou seja, rosto, digital ou PIN.
- **O que conta como ampliar:** uma política nova, ou um host, método, caminho, slot
  ou esquema não cobertos antes. Também contam remover um deny ou um limite de
  caminho, e ligar `allow_exec`. A checagem é conservadora: o que não for
  comprovadamente mais restrito exige aprovação.
- **O desafio** é de uso único, expira em dois minutos e fica vinculado à sessão e a
  um hash do escopo e da política exatos que serão gravados. A aprovação de uma
  alteração não serve para outra.
- **O verificador** confere o desafio, a origem (`http://localhost:<porta>`), o
  relying party (`localhost`), as flags de presença e verificação do usuário, a
  assinatura (RS256, ES256 ou Ed25519) e o contador de assinaturas. Não precisa de
  dependências novas, e o analisador CBOR é limitado e testado com fuzzing.
- **O cadastro** é de onde vem a confiança. O `interpose setup`, ou o
  `interpose service enroll`, cria a credencial pela `webauthn.dll` a partir do
  runtime privado em `%ProgramFiles%` e grava a chave pública na pasta do cofre.
  Os dois lugares são fechados aos processos do usuário, então eles não conseguem
  cadastrar uma chave própria. Um registro danificado mantém a aprovação exigida, em
  vez de desligá-la.

Toda tarefa elevada, exceto a instalação, agora também roda a partir desse runtime
privado, e não da instalação do usuário (que ele pode alterar).

**Riscos residuais.**
- Um processo do mesmo usuário pode fazer o Windows Hello aparecer num momento em
  que o operador espera um pedido, e aproveitar a aprovação. Aprove só logo depois
  de salvar uma alteração você mesmo.
- Sem cadastro (máquina sem Windows Hello), o painel mostra um aviso e as alterações
  ficam sem proteção.
- Trocar o valor de um segredo não exige aprovação: não revela nada, mas pode
  quebrar uma credencial que funcionava.

### 4. Cobertura do mascaramento (média, corrigido)

O mascaramento cobria as formas exata, percent-encoded e base64. Agora também cobre:
- escape JSON (inclusive `\/`) e hex;
- base64 URL-safe, e base64 embutido em qualquer alinhamento de bytes, como em
  `Basic base64(usuario:token)`;
- tudo isso sem diferenciar maiúsculas.

O broker também repassava o `Accept-Encoding` do agente, então o destino podia
responder em `br` ou `zstd`. O mascaramento analisava então bytes comprimidos. Agora
o broker oferece só `gzip, deflate` e recusa (502) respostas em outra codificação.

Um teste baseado em propriedades (Hypothesis) verifica que nenhum reflexo suportado
de um segredo aleatório sobrevive ao mascaramento.

O mascaramento continua sendo defesa em profundidade. A garantia vem dos slots de
injeção e das políticas de host.

### 5. Normalização de hosts Unicode (baixa, corrigido)

A política comparava o host como texto, enquanto o cliente HTTP aplicava
normalização IDNA antes de conectar. Pontos de largura total, `ı` sem pingo e
caracteres parecidos podiam, portanto, ser um host para a política e outro para a
conexão. Hosts não ASCII agora são recusados. Um teste de fuzzing verifica que, para
qualquer `Host` aceito, o host discado é igual ao host da política.

## Verificado e correto

- Userinfo em alvos de forma absoluta é rejeitado. CRLF em valores de header é
  rejeitado pelo cliente HTTP, e o `interpose-exec` recusa caracteres de controle e
  barras invertidas.
- Uma referência usada como *nome* de header, query ou campo de formulário, no corpo
  ou num campo não declarado é negada antes da resolução.
- Redirecionamentos não são seguidos, o `trust_env` fica desligado e o `CONNECT` é
  recusado.
- A política é avaliada antes da resolução, e `EXEC` e HTTP sem TLS exigem
  autorização explícita.
- Os dados associados do AES-GCM vinculam cada texto cifrado ao escopo e à
  referência. Os fingerprints são HMACs com chave.
- Os listeners do loopback recusam `Origin`, `Sec-Fetch-Site` cross-site e `Host`
  fora do loopback. As rotas de controle também recusam requisições com formato de
  navegador.
- Os links de login do painel são de uso único e expiram. As sessões usam cookies
  `HttpOnly` e `SameSite=Strict`, com token CSRF por sessão e CSP restritiva. Os
  valores são só de escrita.
- O serviço não herda `INTERPOSE_MASTER_KEY` nem `INTERPOSE_HOME`, e o launcher monta
  o ambiente dos filhos a partir de uma lista de permitidos.

## Verificações contínuas

- `tests/test_audit_regressions.py` roda em todo pull request no Linux, macOS e
  Windows. Ele inclui fuzzing com Hypothesis da análise de hosts e do mascaramento.
- O CodeQL (`security-extended`) roda em todo pull request e semanalmente. O
  OpenSSF Scorecard roda na `main`.

Relate novos problemas de forma privada: veja o [SECURITY.md](../../SECURITY.md).
