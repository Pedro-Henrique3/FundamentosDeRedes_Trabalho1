# Trabalho 01 - Fundamentos de Redes de Computadores

**Disciplina:** Fundamentos de Redes de Computadores  
**Professor:** Tiago Alves  

## 1. Integrantes
- Davi Camilo Menezes (231011220)
- Euller Julio da Silva (231012094)
- Giovani de Oliveira Teodoro (241032500)
- Pedro Henrique Freire Rodrigues (231026545)

## 2. Ambiente de Desenvolvimento
- **Sistema Operacional:** Windows 11 (build 26200), com a API de sockets POSIX usada pelo roteiro em GNU/Linux
- **Linguagem:** C
- **Compilador:** GCC (MSYS2, ucrt64)
- **Editor/IDE:** VS Code

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
O programa é operado por linha de comando. São obrigatórios dois argumentos: o nome de domínio e o endereço IPv4 do servidor DNS. A consulta é do tipo MX, classe IN, enviada por UDP na porta 53. O cliente espera 2 segundos por resposta e repete a consulta por até 3 vezes.

Sem os dois argumentos, o programa escreve o uso em stderr e encerra:

```
$ ./meu_cliente
Uso: ./meu_cliente <nome_dominio> <ip_servidor_dns>
```

Formatos de saída exigidos pelo roteiro:

```
# Resolução bem sucedida
$ ./meu_cliente unb.br 8.8.8.8
unb.br <> unb-br.mail.protection.outlook.com

# Resolução com falha: nome de domínio não existe
$ ./meu_cliente imagdaskdasdasj.br 1.1.1.1
Dominio imagdaskdasdasj.br nao encontrado

# Resolução com falha: domínio não possui entrada MX
$ ./meu_cliente fga.unb.br 8.8.8.8
Dominio fga.unb.br nao possui entrada MX

# Resolução com falha: servidor não existe ou não atendeu
$ ./meu_cliente unb.br 1.2.3.4
Nao foi possível coletar entrada MX para unb.br
```
