#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

#include "dns.h"

#define RECV_TIMEOUT_SEC 2 // timeout de recepcao (2s)
#define MAX_ATTEMPTS 3     // numero maximo de tentativas

// Função auxiliar para formatar o nome de domínio para o padrão do DNS (QNAME)
// Ex: "unb.br" -> "\x03unb\x02br\x00"
void format_dns_name(unsigned char *dns, const unsigned char *host) {
    int lock = 0, i; // lock: inicio do label atual (trecho entre pontos)
    int host_len = strlen((const char*)host);

    // Itera sobre o nome de domínio
    for (i = 0; i <= host_len; i++) {
        // Se encontrar um ponto ou o final da string
        if (host[i] == '.' || host[i] == '\0') {
            *dns++ = i - lock; // Preenche o byte de tamanho
            for (; lock < i; lock++) {
                *dns++ = host[lock]; // Copia os caracteres
            }
            lock++; // Avança o lock pulando o ponto
        }
    }
    *dns++ = '\0'; // Finaliza o QNAME com 0
}

// Função responsável por montar o payload UDP da consulta DNS
// Devolve o tamanho total do payload e escreve em *out_txid o Transaction ID gerado
int build_dns_query(const char *domain, unsigned char *buffer, uint16_t *out_txid) {
    dns_header_t *dns = (dns_header_t *)buffer;

    // Gera um Transaction ID de 16 bits combinando duas chamadas de rand()
    // (evita o caso em que RAND_MAX < 0xFFFF)
    uint16_t txid = (uint16_t)((rand() & 0xFFFF) ^ ((rand() & 0xFF) << 8));
    if (out_txid) {
        *out_txid = txid;
    }

    // Header (12 bytes)
    dns->id = htons(txid);             // ID aleatório; htons = host para network order
    dns->flags = htons(0x0100);        // RD=1: pede resposta recursiva
    dns->qdcount = htons(0x0001);      // 1 pergunta
    dns->ancount = htons(0x0000);      // consulta não traz respostas
    dns->nscount = htons(0x0000);      // nem registros de autoridade
    dns->arcount = htons(0x0000);      // nem registros adicionais

    // A seção Question começa logo após o cabeçalho
    unsigned char *qname = &buffer[sizeof(dns_header_t)];

    // Copia o domínio para um buffer local e garante o '\0' final
    char host[256];
    strncpy(host, domain, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';

    // Converte o nome de domínio para o formato do DNS
    format_dns_name(qname, (unsigned char*)host);

    // Avança o ponteiro para depois do nome (strlen funciona pois não há '\0' no meio)
    int qname_len = strlen((const char*)qname) + 1; // +1 inclui o byte 0 final
    unsigned char *qinfo = qname + qname_len;       // QTYPE e QCLASS vêm aqui

    // Define QTYPE (Tipo) = MX (15)
    uint16_t qtype = htons(QTYPE_MX);
    memcpy(qinfo, &qtype, sizeof(qtype));
    qinfo += sizeof(qtype);

    // Define QCLASS (Classe) = IN (1)
    uint16_t qclass = htons(QCLASS_IN);
    memcpy(qinfo, &qclass, sizeof(qclass));
    qinfo += sizeof(qclass);

    // Retorna o tamanho total do payload gerado
    return (qinfo - buffer);
}

// Lê um nome no formato DNS, tratando também ponteiros de compressão.
// Retorna a quantidade de bytes consumidos na posição original (retorna -1 em caso de erro).
int read_dns_name(const unsigned char *msg,
                  int msg_len,
                  int offset,
                  char *out,
                  int out_size) {

    int pos = offset;  // onde ler agora (pode saltar ao seguir um ponteiro)
    int out_pos = 0;   // próxima posição livre na string "a.b.c"
    int consumed = 0;  // bytes ocupados no offset original, sem seguir ponteiros
    int jumped = 0;    // 1 depois do primeiro ponteiro de compressão

    // Evita loop infinito caso exista um pacote malformado
    int jumps = 0;

    if (offset < 0 || offset >= msg_len || out_size <= 0) {
        return -1;
    }

    while (pos < msg_len) {
        unsigned char len = msg[pos];
        // Fim do nome
        if (len == 0) {
            if (!jumped) {
                consumed++; // o byte 0 de fim também conta no nome original
            }
            break;
        }

        // Ponteiro de compressão DNS:
        // os dois bits mais significativos são 11
        if ((len & 0xC0) == 0xC0) {
            // O ponteiro ocupa 2 bytes
            if (pos + 1 >= msg_len) {
                return -1;
            }

            // Os 14 bits baixos são o deslocamento do nome dentro do pacote
            int pointer =
                ((msg[pos] & 0x3F) << 8) |
                msg[pos + 1];

            if (pointer >= msg_len) {
                return -1;
            }

            if (!jumped) {
                consumed += 2; // no lugar do nome só existem estes 2 bytes
            }

            pos = pointer; // continua lendo o nome no offset apontado
            jumped = 1;

            // Proteção contra ponteiros circulares
            jumps++;

            if (jumps > msg_len) {
                return -1;
            }
            continue;
        }

        // Labels DNS não podem usar os bits reservados 01 ou 10
        if ((len & 0xC0) != 0) {
            return -1;
        }

        // Avança para o conteúdo do label
        pos++;

        if (!jumped) {
            consumed++; // conta o byte de tamanho do label
        }

        // Verifica se o label cabe dentro da mensagem
        if (pos + len > msg_len) {
            return -1;
        }

        // Adiciona ponto entre os labels
        if (out_pos > 0) {
            if (out_pos >= out_size - 1) {
                return -1;
            }
            out[out_pos++] = '.';
        }

        // Copia os caracteres do label
        for (int i = 0; i < len; i++) {
            if (out_pos >= out_size - 1) {
                return -1;
            }
            out[out_pos++] = msg[pos + i];
        }

        pos += len;

        if (!jumped) {
            consumed += len; // conta os caracteres; após um salto, não conta
        }
    }

    if (pos >= msg_len) {
        return -1;
    }

    out[out_pos] = '\0'; // fecha a string legível ("mail.unb.br")

    return consumed; // bytes a pular no offset original para o próximo campo
}

// Interpreta a resposta DNS, procura registros MX e imprime o resultado no formato solicitado.
// expected_txid é o Transaction ID enviado na consulta; respostas com ID diferente são descartadas.
int parse_dns_response(const unsigned char *response,
                       int response_len,
                       const char *domain,
                       uint16_t expected_txid) {

    // A resposta precisa ter pelo menos o cabeçalho DNS
    if (response_len < (int)sizeof(dns_header_t)) {
        fprintf(stderr, "Resposta DNS invalida.\n");
        return -1;
    }

    // Interpreta os primeiros 12 bytes como cabeçalho DNS
    const dns_header_t *header =
        (const dns_header_t *)response;

    // Confere se a resposta é realmente a resposta da nossa consulta
    uint16_t resp_id = ntohs(header->id);
    if (resp_id != expected_txid) {
        fprintf(stderr,
                "Transaction ID inesperado: esperado 0x%04x, recebido 0x%04x\n",
                expected_txid, resp_id);
        return -1;
    }

    uint16_t flags = ntohs(header->flags);     // ntohs: network order para o host
    uint16_t qdcount = ntohs(header->qdcount); // quantas perguntas repetir/pular
    uint16_t ancount = ntohs(header->ancount); // quantos registros de resposta ler

    // Os últimos 4 bits das flags representam o RCODE
    int rcode = flags & 0x000F;

    // RCODE 3 = NXDOMAIN.
    // Acentuação gravada como escape UTF-8 ("\xc3\xad") para não depender
    // do encoding do arquivo-fonte e casar exatamente com o enunciado.
    if (rcode == 3) {
        printf("Dom\xc3\xadnio %s nao encontrado\n", domain);
        return 0;
    }

    // Outro erro retornado pelo servidor DNS
    if (rcode != 0) {
        fprintf(stderr,
                "Erro DNS ao consultar %s (RCODE = %d)\n",
                domain,
                rcode);
        return -1;
    }

    int offset = sizeof(dns_header_t); // primeiro byte depois do cabeçalho de 12 bytes
    /*
     * Pula a seção Question.
     *
     * Cada Question possui:
     * QNAME
     * QTYPE  - 2 bytes
     * QCLASS - 2 bytes
     */
    for (int i = 0; i < qdcount; i++) {
        char question_name[256];

        int consumed = read_dns_name(
            response,
            response_len,
            offset,
            question_name,
            sizeof(question_name)
        );

        if (consumed < 0) {
            fprintf(stderr,
                    "Erro ao interpretar a secao Question.\n");
            return -1;
        }

        offset += consumed; // passa do QNAME para QTYPE

        // QTYPE + QCLASS
        if (offset + 4 > response_len) {
            fprintf(stderr,
                    "Resposta DNS truncada na secao Question.\n");
            return -1;
        }
        offset += 4; // pula QTYPE (2 bytes) e QCLASS (2 bytes)
    }

    // Guarda o MX de menor preference encontrado.
    // Se o domínio tiver vários MXs, queremos imprimir apenas o de maior prioridade
    // (menor valor de preference, conforme RFC 1035).
    int mx_found = 0;                 // 1 se algum MX de classe IN foi encontrado
    int best_preference = 0x7FFFFFFF; // "infinito" inicial
    char best_mx_name[256];
    best_mx_name[0] = '\0';

    /*
     * Percorre todos os registros da seção Answer.
     *
     * Formato de cada Resource Record (RR):
     * NAME
     * TYPE       2 bytes
     * CLASS      2 bytes
     * TTL        4 bytes
     * RDLENGTH   2 bytes
     * RDATA      variável
     */
    for (int i = 0; i < ancount; i++) {
        char answer_name[256];

        int consumed = read_dns_name(
            response,
            response_len,
            offset,
            answer_name,
            sizeof(answer_name)
        );

        if (consumed < 0) {
            fprintf(stderr,
                    "Erro ao interpretar nome da resposta DNS.\n");
            return -1;
        }

        offset += consumed; // NAME da resposta; em seguida vêm os campos fixos

        // TYPE + CLASS + TTL + RDLENGTH = 10 bytes
        if (offset + 10 > response_len) {
            fprintf(stderr,
                    "Resposta DNS truncada.\n");
            return -1;
        }

        uint16_t type;
        memcpy(&type, response + offset, sizeof(type));
        type = ntohs(type); // 15 = MX, 1 = A, 5 = CNAME
        offset += 2;

        uint16_t class;
        memcpy(&class, response + offset, sizeof(class));
        class = ntohs(class); // 1 = IN (Internet)
        offset += 2;

        // TTL possui 4 bytes: por quanto tempo o registro pode ser cacheado.
        offset += 4;

        uint16_t rdlength;
        memcpy(
            &rdlength,
            response + offset,
            sizeof(rdlength)
        );

        rdlength = ntohs(rdlength); // tamanho, em bytes, do RDATA que segue
        offset += 2;

        // Verifica se o RDATA está inteiro dentro da resposta
        if (offset + rdlength > response_len) {
            fprintf(stderr,
                    "RDATA invalido ou resposta DNS truncada.\n");
            return -1;
        }

        if (type == QTYPE_MX &&
            class == QCLASS_IN) {
            if (rdlength < 3) {
                fprintf(stderr,
                        "Registro MX invalido.\n");
                return -1;
            }

            // Preference (prioridade do MX) ocupa os 2 primeiros bytes; o nome vem depois.
            uint16_t preference;
            memcpy(&preference, response + offset, sizeof(preference));
            preference = ntohs(preference);

            int mx_name_offset = offset + 2; // pula os 2 bytes de preference

            char mx_name[256];

            if (read_dns_name(
                    response,
                    response_len,
                    mx_name_offset,
                    mx_name,
                    sizeof(mx_name)
                ) < 0) {
                fprintf(stderr,
                        "Erro ao interpretar servidor MX.\n");
                return -1;
            }

            // Só guarda se for a melhor preference vista até agora
            if (preference < best_preference) {
                best_preference = preference;
                strncpy(best_mx_name, mx_name, sizeof(best_mx_name) - 1);
                best_mx_name[sizeof(best_mx_name) - 1] = '\0';
            }
            mx_found = 1;
        }
        /*
         * Avança para o próximo Resource Record.
         *
         * É importante usar rdlength, pois o RDATA pode ter tamanho variável.
         */
        offset += rdlength;
    }

    // Imprime o resultado final
    if (mx_found) {
        // Requisito do trabalho: uma linha no formato "nome <> servidor_email"
        printf("%s <> %s\n", domain, best_mx_name);
    } else {
        // A consulta funcionou, mas nenhum registro MX apareceu
        printf("Dom\xc3\xadnio %s nao possui entrada MX\n", domain);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    srand(time(NULL)); // Semente para o gerador do Transaction ID

    if (argc != 3) { // argv[0] = programa, [1] = domínio, [2] = IP
        fprintf(stderr, "Uso: %s <nome_dominio> <ip_servidor_dns>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *domain = argv[1];     // nome consultado, ex.: "unb.br"
    const char *dns_server = argv[2]; // IP do servidor, ex.: "8.8.8.8"

    // AF_INET = IPv4, SOCK_DGRAM = datagrama (UDP), IPPROTO_UDP = protocolo UDP
    int socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socketfd < 0) {
        perror("Erro ao criar socket");
        exit(EXIT_FAILURE);
    }

     // Timeout de recepção (2s): recvfrom desiste se nada chegar nesse prazo
     struct timeval tv; // struct definida em <sys/time.h>: tv_sec + tv_usec
     tv.tv_sec  = RECV_TIMEOUT_SEC; // segundos
     tv.tv_usec = 0;                // microssegundos (0 => timeout exato de 2s)

     // setsockopt: define opções do socket
     // SO_RCVTIMEO: configura o timeout de recepção do socket

     if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO,
                    (const char*)&tv, sizeof(tv)) < 0) {
         perror("Erro ao configurar SO_RCVTIMEO");
         close(socketfd);
         exit(EXIT_FAILURE);
     }

    // Configuracao do endereco do servidor (struct sockaddr_in)
    struct sockaddr_in dest;            // IP e porta de destino
    memset(&dest, 0, sizeof(dest));     // zera campos não preenchidos
    dest.sin_family = AF_INET;          // família IPv4
    dest.sin_port = htons(DNS_PORT);    // porta 53 em network byte order
    if (inet_pton(AF_INET, dns_server, &dest.sin_addr) <= 0) { // texto "a.b.c.d" -> binário
        fprintf(stderr, "IP do servidor invalido: %s\n", dns_server);
        close(socketfd);
        exit(EXIT_FAILURE);
    }

    // Montagem do pacote DNS (Header + Question) programaticamente
    unsigned char query_buf[65536]; // pacote de consulta (cabeçalho e question)
    uint16_t txid = 0;              // Transaction ID gerado pela consulta
    int query_len = build_dns_query(domain, query_buf, &txid); // quantos bytes enviar

    // Loop para enviar a requisicao e aguardar resposta (até 3 tentativas)
    unsigned char resp_buf[65536]; // pacote de resposta
    ssize_t resp_len = -1;         // fica > 0 só quando um datagrama chega

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        // flag 0 = sem opções; dest leva IP e porta do servidor DNS
        ssize_t sent = sendto(socketfd, query_buf, query_len, 0,
                              (struct sockaddr *)&dest, sizeof(dest));
        if (sent < 0) {
            perror("Erro no sendto");
            continue;           // tenta de novo (se ainda houver tentativa)
        }

        resp_len = recvfrom(socketfd, resp_buf, sizeof(resp_buf), 0,
                            NULL, NULL); // bloqueia até o timeout; origem não é usada

        if (resp_len > 0) {
            break;              // resposta recebida: sai do loop
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) { // SO_RCVTIMEO estourou
            fprintf(stderr,
                    "Tentativa %d/%d: timeout apos %d segundos.\n",
                    attempt, MAX_ATTEMPTS, RECV_TIMEOUT_SEC);
        } else {
            perror("Erro no recvfrom");
        }
    }

    // Trata falha total (3 timeouts/erros)
    if (resp_len <= 0) {
        printf("Nao foi possível coletar entrada MX para %s\n", domain);
        close(socketfd);
        return EXIT_FAILURE;
    }

    // Interpreta os bytes da resposta e imprime o resultado no formato esperado
    int parse_result = parse_dns_response(resp_buf, resp_len, domain, txid);

    close(socketfd); // libera o descritor do socket

    if (parse_result < 0) { // pacote malformado ou RCODE de erro
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS; // resposta interpretada: MX impresso, NXDOMAIN ou sem MX
}