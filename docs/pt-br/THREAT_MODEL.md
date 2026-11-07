[English](../en/THREAT_MODEL.md) | **Português (Brasil)**

# Modelo de Ameaças

## Resumo

Agentes, IDEs, código gerado, arquivos do projeto e processos filhos são não confiáveis. O cofre de segredos, o motor de políticas, o broker, o motor de mascaramento e o gravador de auditoria formam a zona confiável.

O modelo preferido é a execução só com referências: processos não confiáveis recebem valores `secret://` e um broker de protocolo confiável executa a operação que exige o valor em texto puro. O `interpose-exec` é um modo de compatibilidade limitado, porque o subprocesso dele recebe os argumentos já resolvidos.

## Ameaças

| Ameaça | Situação | Observações |
| --- | --- | --- |
| Prompt injection | Parcialmente protegido | As referências continuam opacas, mas um agente manipulado pode tentar operações não suportadas ou saída de rede direta. |
| Código gerado malicioso | Parcialmente protegido | O launcher entrega só referências. Com o serviço do Windows o vault fica fora do alcance do código; a saída de rede ainda não é controlada, e sem o serviço um processo do mesmo usuário consegue ler o vault. |
| Exfiltração de segredo por um destino HTTP permitido | Parcialmente protegido | As políticas de host, método, caminho e slot de injeção são checadas antes da resolução. Uma referência no corpo ou num header/campo não declarado é negada, então uma API permitida não pode ser usada para publicá-la ou ecoá-la. Um slot permitido num endpoint que a reflete continua sendo risco residual; restrinja `paths`. |
| Credenciais herdadas do ambiente | Protegido em sessões gerenciadas | O launcher monta o ambiente do filho a partir de uma lista de permissão e injeta só as referências declaradas. |
| Inspeção do ambiente | Protegido em sessões gerenciadas | A inspeção revela referências. Processos iniciados fora do `interpose run` estão fora do escopo. |
| Inspeção do sistema de arquivos | Protegido no Windows com o serviço; não protegido no modo de desenvolvimento | Com `interpose setup` o vault e a chave ficam em `%ProgramData%\Interpose\vault`, acessíveis só a `NT SERVICE\Interpose`, SYSTEM e administradores, e o serviço executa código de `%ProgramFiles%`, que o usuário não pode alterar. O setup recusa uma pasta de dados pré-existente que não pertença a Administrators ou que contenha links, para que ninguém a deixe preparada com uma chave conhecida. No modo de desenvolvimento um processo do mesmo usuário consegue ler o banco e o arquivo da chave. Um processo elevado consegue ler tudo nos dois modos. |
| Personificação do painel | Protegido com o serviço | Um processo que ocupe a porta do painel poderia se passar por ele e coletar os valores digitados. O `interpose up` confere que as duas portas pertencem ao processo do serviço antes de abrir um link de login. |
| Token de controle do serviço | Ainda não protegido | O token que os clientes usam para pedir links de login no painel é legível pelo usuário que instalou, então um processo do mesmo usuário pode abrir uma sessão no painel e alterar políticas ou trocar valores (nunca lê-los). Exigir presença do usuário com o Windows Hello nas sessões do painel é a correção planejada. |
| Acesso à API administrativa | Parcialmente protegido | Exige um token bearer gerado a cada início, impresso no terminal do operador e nunca gravado. Um processo do mesmo usuário que consiga ler o terminal do operador ou a memória da API ainda pode obtê-lo. |
| Acesso ao painel | Parcialmente protegido | Link de login de uso único trocado por um cookie `HttpOnly` e `SameSite=Strict`; checagens de `Host` no loopback e de mesma origem; token CSRF por sessão em toda alteração; CSP restritiva; valores só de escrita. Um processo do mesmo usuário que leia o terminal antes de o operador abrir o link, ou que controle o navegador já logado do operador, consegue agir como o operador. |
| Acesso a segredos de outro projeto | Protegido em sessões gerenciadas | O projeto ativo vem do registro do operador, não de arquivos do workspace. Os textos cifrados de projeto ficam vinculados ao escopo pelos dados associados do AES-GCM. |
| Reflexo parcial pelo destino | Não protegido | Algumas APIs ecoam a chave mascarada em erros (`sk_test_****abcd`). O mascaramento por valor exato não pega ecos parciais, então alguns caracteres podem chegar ao agente. |
| Acesso a listeners do loopback via navegador | Protegido | O broker e a API rejeitam requisições com header `Origin` ou `Sec-Fetch-Site` cross-site e rejeitam headers `Host` fora do loopback, bloqueando CSRF e DNS rebinding vindos de páginas web. |
| `/proc` ou inspeção de processos | Parcialmente protegido | Sessões só com referências não têm argumentos secretos. O `interpose-exec` pode expor argumentos resolvidos. |
| Inspeção da memória de processos | Ainda não protegido | O isolamento entre broker e agente do mesmo usuário não é aplicado. |
| Exfiltração direta pela rede | Ainda não protegido | O transporte local explícito não impede um agente de abrir sockets diretos. O controle de saída no sistema operacional continua obrigatório. |
| Exfiltração pelo broker HTTP | Parcialmente protegido | Políticas de destino, método e esquema são aplicadas antes da resolução. Faltam controles de DNS rebinding e de caminho. |
| Tráfego HTTPS | Ainda não protegido | `CONNECT` é rejeitado porque um túnel TLS opaco não permite substituir referências com segurança. |
| Redirecionamentos HTTP | Protegido | Redirecionamentos automáticos do destino estão desativados. |
| Referências URL-encoded | Protegido em query/formulário HTTP | O broker decodifica as referências, avalia a política, resolve e recodifica os valores com segurança. |
| Adivinhação por fingerprint | Protegido | Os fingerprints são HMAC-SHA256 com uma chave derivada da chave mestra, então um fingerprint listado não serve de oráculo offline para segredos de baixa entropia. Fingerprints SHA-256 antigos são reescritos ao abrir. |
| Desvio de destino no `interpose-exec` | Parcialmente protegido | Exige `allow_exec: true` por segredo e o método `EXEC` explícito para comandos que não são curl; conta hosts do curl sem esquema e recusa opções do curl que redirecionam o tráfego. A inferência pelos argumentos continua sendo uma heurística. |
| Logs e auditoria | Protegido para valores resolvidos conhecidos | Valores e URLs resolvidos são mascarados; os registros de auditoria contêm só referências e metadados. |
| Atribuição na auditoria | Ainda não protegido | O broker não autentica clientes no loopback, então não consegue verificar qual processo enviou a requisição. Os registros são confiáveis sobre o que aconteceu, não sobre quem fez. |
| Stack traces | Parcialmente protegido | Os erros do broker são mascarados. Stack traces de aplicações não confiáveis contêm só referências em sessões gerenciadas. |
| Reflexo na resposta | Parcialmente protegido | Valores resolvidos conhecidos são mascarados em headers e corpos, inclusive corpos binários que não são UTF-8. Reflexos codificados ou transformados podem escapar do mascaramento exato; os slots de injeção mantêm referências fora de corpos que o destino transformaria. |
| Exfiltração por DNS | Ainda não protegido | O DNS não é controlado no nível do sistema operacional. |
| Certificate pinning | Ainda não protegido | A futura terminação TLS transparente não vai funcionar para clientes com pinning sem integração explícita. |
| Uso criptográfico local | Futuro | Assinatura, mTLS, SSH e SigV4 exigem brokers de operação; devolver material de chave é proibido. |

## Garantias

A implementação atual garante que:

1. nenhuma operação pública da API ou da CLI retorna um valor de segredo armazenado;
2. as políticas do broker — host, método, esquema, caminho e slot de injeção — são avaliadas antes da resolução do segredo;
3. os ambientes dos filhos gerenciados contêm as referências declaradas, e não valores resolvidos;
4. o launcher não repassa `INTERPOSE_MASTER_KEY` nem `INTERPOSE_HOME` aos filhos;
5. o armazenamento local de segredos usa criptografia autenticada;
6. os registros de auditoria não gravam intencionalmente segredos em texto puro;
7. HTTP `CONNECT` é rejeitado em vez de criar uma falsa garantia de HTTPS transparente;
8. o transporte local explícito extrai o destino de `/proxy/{host}` e usa HTTPS por padrão para tráfego externo;
9. os listeners do loopback recusam requisições vindas de navegador e de DNS rebinding, e a API administrativa exige um token;
10. com o serviço do Windows instalado, o vault e a chave mestra só podem ser lidos por `NT SERVICE\Interpose`, SYSTEM e administradores, e o serviço só carrega código de `%ProgramFiles%\Interpose`.

## O que não é garantido

A implementação atual não garante proteção contra:

1. um processo malicioso rodando com o mesmo usuário do sistema operacional que o broker no modo de desenvolvimento, ou um que use o token de controle do serviço para alterar políticas pelo painel;
2. um processo rodando elevado (administrador ou SYSTEM);
3. acesso direto à rede que contorne o transporte local;
4. leitura da memória do broker confiável;
5. canais encobertos, DNS, QUIC ou transportes não gerenciados;
6. segredos entregues pelo modo de compatibilidade limitado `interpose-exec`;
7. SDKs que exigem o valor em texto puro localmente para validar, derivar, cifrar ou assinar.
