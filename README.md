# Trabalho 01 - Fundamentos de Redes de Computadores

**Disciplina:** Fundamentos de Redes de Computadores  
**Professor:** Tiago Alves  

## 1. Integrantes
- Nome Sobrenome (Matrícula)
- Nome Sobrenome (Matrícula)

## 2. Ambiente de Desenvolvimento
- **Sistema Operacional:** Linux (Especificar versão/distribuição)
- **Linguagem:** C
- **Compilador:** GCC
- **Editor/IDE:** (Especificar)

## 3. Como Construir a Aplicação
Para compilar o código, basta utilizar o Makefile incluso na raiz do projeto. No terminal, execute o seguinte comando:

```bash
make
```

Isso criará o executável `meu_cliente` na raiz do diretório.

## 4. Como Executar a Aplicação
Após a compilação, o cliente pode ser executado passando dois argumentos: o nome de domínio a ser consultado e o IP do servidor DNS.

**Sintaxe:**
```bash
./meu_cliente <nome_dominio> <ip_servidor_dns>
```

**Exemplo:**
```bash
./meu_cliente unb.br 8.8.8.8
```

## 5. Telas / Instruções de Uso
O programa é operado inteiramente por interface de linha de comando (CLI). A saída padrão informará o resultado da consulta no formato especificado:

```
# Resolução bem sucedida
$ ./meu_cliente unb.br 8.8.8.8
unb.br <> unb-br.mail.protection.outlook.com
```

## 6. Limitações Conhecidas
- (Descreva quaisquer limitações, por exemplo, não resolve registros CNAME, apenas extrai a primeira entrada MX, etc.)
