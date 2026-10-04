# Trabalho 01 - Fundamentos de Redes de Computadores

**Disciplina:** Fundamentos de Redes de Computadores  
**Professor:** Tiago Alves  

## 1. Integrantes
- Davi Camilo Menezes (231011220)
- Euller Júlio da Silva (231026714)
- Giovani de Oliveira Teodoro Coelho (241032500)
- Pedro Henrique Freire Rodrigues (231026545)

## 2. Ambiente de Desenvolvimento
- **Qual sistema operacional foi usado na construção do sistema:** Windows 11 (build 26200), com a API de sockets POSIX usada pelo roteiro em GNU/Linux
- **Qual ambiente de desenvolvimento foi usado:** MSYS2 (terminal MSYS), com o GCC desse ambiente. O código usa sockets POSIX (`unistd.h`, `arpa/inet.h`, `sys/socket.h`).
- **Linguagem:** C
- **Compilador:** GCC (MSYS2, ucrt64)
- **Editor/IDE:** VS Code

## 3. Como construir a aplicação
Para compilar o código, basta utilizar o Makefile incluso na raiz do projeto. No terminal, execute o seguinte comando:

```bash
make
```

Também é possível compilar diretamente com o GCC, sem utilizar o Makefile:

```bash
gcc -Wall -Wextra -I./include src/cliente.c -o meu_cliente
```

Isso criará o executável `meu_cliente` na raiz do diretório.

## 4. Como executar a aplicação
Após a compilação, o cliente pode ser executado passando dois argumentos: o nome de domínio a ser consultado e o IP do servidor DNS.

**Sintaxe:**
```bash
./meu_cliente <nome_dominio> <ip_servidor_dns>
```

**Exemplo:**
```bash
./meu_cliente unb.br 8.8.8.8
```

## 5. Quais são as telas (instruções de uso)
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

## 6. Quais são as limitações conhecidas
- O servidor DNS precisa ser um endereço IPv4. Um IPv6 é recusado na validação do argumento.
- A consulta é somente MX, classe IN. Se o domínio tiver vários registros MX, o programa imprime apenas o de menor valor de preference.
- A troca é só por UDP. Se a resposta vier truncada (bit TC), o cliente não repete a consulta por TCP.
- Só a seção Answer é lida. Registros MX que apareçam apenas nas seções Authority ou Additional são ignorados.
- A espera por resposta é fixa: 2 segundos por tentativa, no máximo 3 tentativas.
- O nome de domínio é copiado para um buffer de 256 bytes. Um nome maior que isso é cortado antes da consulta.