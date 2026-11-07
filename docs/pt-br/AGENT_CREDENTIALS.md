[English](../en/AGENT_CREDENTIALS.md) | **Português (Brasil)**

# Contrato de Credenciais para Agentes

## Objetivo

Este contrato é a instrução canônica para Codex, Claude Code, Cursor, Gemini CLI e outros agentes locais não confiáveis.

> As instruções abaixo são para colar no arquivo de instruções do agente. A versão em inglês
> ([`../en/AGENT_CREDENTIALS.md`](../en/AGENT_CREDENTIALS.md)) é a de referência; use esta se o
> seu agente trabalha em português.

## Comportamento exigido

Variáveis de credencial contêm referências `secret://` opacas, nunca valores em texto puro.

Quando for pedido para configurar uma credencial:

1. Escreva a referência pedida na variável de ambiente ou no campo de configuração esperado.
2. Normalize atalhos como `APIChave/teste` para `secret://apichave/teste`.
3. Nunca peça o valor em texto puro quando houver uma referência disponível.
4. Nunca troque uma referência por `****`, um token falso ou um valor fixo no código.
5. Nunca implemente código que resolva uma referência.
6. Nunca inspecione o banco do Interpose, a chave mestra, a memória de processos ou a API administrativa.
7. Use a variável normalmente. O plano de dados confiável intermedeia as operações suportadas.
8. Quando uma URL base do broker for fornecida, configure a variável normal de URL base da aplicação para usá-la. Não reconstrua requisições individuais.
9. Nunca troque `/proxy/{host-permitido}` por outro destino para contornar a política.
10. Em caso de `PolicyViolation`, informe a referência, o destino, o método, o esquema e a capacidade pedida. Não contorne a política.
11. Se uma biblioteca rejeitar referências antes de chegar a um broker, informe que é uma operação com segredo local não suportada. Não peça o segredo.
12. Coloque referências só onde a credencial pertence — normalmente no header `Authorization` ou `X-API-Key`. Nunca coloque uma referência no corpo de uma requisição, numa mensagem, num prompt ou em qualquer campo que uma API armazene ou ecoe. O broker nega esses casos, e tentar é uma violação de política.

## Exemplos

Vínculo pedido:

```text
Defina API_KEY com a credencial APIChave/teste.
```

`.env` correto:

```dotenv
API_KEY=secret://apichave/teste
API_BASE=http://127.0.0.1:9876/proxy/api.exemplo.com
# ou, dentro de um projeto registrado: http://127.0.0.1:9876/p/<projeto>/proxy/api.exemplo.com
```

`.env` incorreto:

```dotenv
API_KEY=valor-em-texto-puro
API_KEY=****
API_BASE=https://api.exemplo.com
```

Aplicações podem ler ou imprimir a variável, porque ela contém só a referência:

```python
import os

assert os.environ["API_KEY"] == "secret://apichave/teste"
```

## Adaptadores para IDEs

O `interpose agents install` escreve uma versão pronta destas regras, com exemplos de uso, em `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` e numa regra do Cursor; o `interpose agents print` imprime o texto para ferramentas configuradas por uma tela de ajustes.

Mantenha este contrato como fonte da verdade e repita o comportamento exigido no arquivo de instruções suportado por cada agente, como `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` e as regras de workspace do Cursor.

Arquivos de instrução são apenas orientação. A segurança de fato vem do launcher só com referências, dos brokers confiáveis, do motor de políticas, dos controles de acesso do sistema operacional e do isolamento de rede.

## Planos de controle e de dados

O plano de controle pode listar referências, metadados, capacidades e políticas. Ele nunca deve retornar valores de segredos.

O plano de dados recebe operações contendo referências, valida o destino e o propósito delas, resolve dentro do broker confiável, executa a operação, mascara as saídas e devolve só resultados seguros.
