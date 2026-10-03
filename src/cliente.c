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

#define MAX_ATTEMPTS 3 // numero maximo de tentativas
#define RECV_TIMEOUT_SEC 2 // timeout de recepcao (2s)
#define DEBUG 0

// Função auxiliar para formatar o nome de domínio para o padrão do DNS (QNAME)
// Ex: "unb.br" -> "\x03unb\x02br\x00"
void format_dns_name(unsigned char *dns, const unsigned char *host) {
    int lock = 0, i;
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
int build_dns_query(const char *domain, unsigned char *buffer) {
    dns_header_t *dns = (dns_header_t *)buffer;

    // Header (12 bytes)
    dns->id = htons((uint16_t)rand()); // ID aleatório
    dns->flags = htons(0x0100);        // Recursão desejada (0x0100)
    dns->qdcount = htons(0x0001);      // 1 pergunta
    dns->ancount = htons(0x0000);
    dns->nscount = htons(0x0000);
    dns->arcount = htons(0x0000);

    // A seção Question começa logo após o cabeçalho
    unsigned char *qname = &buffer[sizeof(dns_header_t)];

    // Cria uma cópia do domínio pois format_dns_name faz alterações na string
    char host[256];
    strncpy(host, domain, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';

    // Converte o nome de domínio para o formato do DNS
    format_dns_name(qname, (unsigned char*)host);

    // Avança o ponteiro para depois do nome (strlen funciona pois não há '\0' no meio)
    int qname_len = strlen((const char*)qname) + 1;
    unsigned char *qinfo = qname + qname_len;

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

    int pos = offset;
    int out_pos = 0;
    int consumed = 0;
    int jumped = 0;

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
                consumed++;
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

            int pointer =
                ((msg[pos] & 0x3F) << 8) |
                msg[pos + 1];

            if (pointer >= msg_len) {
                return -1;
            }

            if (!jumped) {
                consumed += 2;
            }

            pos = pointer;
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
            consumed++;
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
            consumed += len;
        }
    }

    if (pos >= msg_len) {
        return -1;
    }

    out[out_pos] = '\0';

    return consumed;
}

// Interpreta a resposta DNS, procura registros MX e imprime o resultado no formato solicitado.
int parse_dns_response(const unsigned char *response,
                       int response_len,
                       const char *domain) {

    // A resposta precisa ter pelo menos o cabeçalho DNS
    if (response_len < (int)sizeof(dns_header_t)) {
        fprintf(stderr, "Resposta DNS invalida.\n");
        return -1;
    }

    // Interpreta os primeiros 12 bytes como cabeçalho DNS
    const dns_header_t *header =
        (const dns_header_t *)response;

    uint16_t flags = ntohs(header->flags);
    uint16_t qdcount = ntohs(header->qdcount);
    uint16_t ancount = ntohs(header->ancount);

    // Os últimos 4 bits das flags representam o RCODE
    int rcode = flags & 0x000F;

    // RCODE 3 = NXDOMAIN
    if (rcode == 3) {
        printf("Dominio %s nao encontrado\n", domain);
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

    int offset = sizeof(dns_header_t);
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

        offset += consumed;

        // QTYPE + QCLASS
        if (offset + 4 > response_len) {
            fprintf(stderr,
                    "Resposta DNS truncada na secao Question.\n");
            return -1;
        }
        offset += 4;
    }

    int mx_found = 0;
    /*
     * Percorre todos os registros da seção Answer.
     *
     * Formato de cada Resource Record:
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

        offset += consumed;

        // TYPE + CLASS + TTL + RDLENGTH = 10 bytes
        if (offset + 10 > response_len) {
            fprintf(stderr,
                    "Resposta DNS truncada.\n");
            return -1;
        }

        uint16_t type;
        memcpy(&type, response + offset, sizeof(type));
        type = ntohs(type);
        offset += 2;

        uint16_t class;
        memcpy(&class, response + offset, sizeof(class));
        class = ntohs(class);
        offset += 2;

        // TTL possui 4 bytes.
        offset += 4;

        uint16_t rdlength;
        memcpy(
            &rdlength,
            response + offset,
            sizeof(rdlength)
        );

        rdlength = ntohs(rdlength);
        offset += 2;

        // Verifica se o RDATA está inteiro dentro da resposta
        if (offset + rdlength > response_len) {
            fprintf(stderr,
                    "RDATA invalido ou resposta DNS truncada.\n");
            return -1;
        }
        /*
         * O interesse é:
         * TYPE  = MX (15)
         * CLASS = IN (1)
         */
        if (type == QTYPE_MX &&
            class == QCLASS_IN) {
            /*
             * RDATA de um registro MX:
             *
             * +------------+
             * | Preference | 2 bytes
             * +------------+
             * | Exchange   | nome DNS
             * +------------+
             */

            if (rdlength < 3) {
                fprintf(stderr,
                        "Registro MX invalido.\n");
                return -1;
            }

            // Preference ocupa os primeiros 2 bytes.
            int mx_name_offset = offset + 2;

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

            printf(
                "%s <> %s\n",
                domain,
                mx_name
            );
            mx_found = 1;
        }
        /*
         * Avança para o próximo Resource Record.
         *
         * É importante usar rdlength, pois o RDATA pode ter tamanho variável.
         */
        offset += rdlength;
    }

    // A consulta funcionou, mas nenhum registro MX apareceu
    if (!mx_found) {
        printf(
            "Dominio %s nao possui entrada MX\n",
            domain
        );
    }
    return 0;
}

int main(int argc, char *argv[]) {
    srand(time(NULL)); // Semente para o gerador do Transaction ID

    if (argc != 3) {
        fprintf(stderr, "Uso: %s <nome_dominio> <ip_servidor_dns>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *domain = argv[1];
    const char *dns_server = argv[2];

    // Comunicacao UDP: criacao do socket
    int socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socketfd < 0) {
        perror("Erro ao criar socket");
        exit(EXIT_FAILURE);
    }

     // Timeout de recepção (2s)
     struct timeval tv;
     tv.tv_sec  = RECV_TIMEOUT_SEC;
     tv.tv_usec = 0;
     if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO,
                    (const char*)&tv, sizeof(tv)) < 0) {
         perror("Erro ao configurar SO_RCVTIMEO");
         close(socketfd);
         exit(EXIT_FAILURE);
     }

    // Configuracao do endereco do servidor (struct sockaddr_in)
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(DNS_PORT);
    if (inet_pton(AF_INET, dns_server, &dest.sin_addr) <= 0) {
        fprintf(stderr, "IP do servidor invalido: %s\n", dns_server);
        close(socketfd);
        exit(EXIT_FAILURE);
    }

    // Montagem do pacote DNS (Header + Question) programaticamente
    unsigned char query_buf[65536];
    int query_len = build_dns_query(domain, query_buf);

    // Loop para enviar a requisicao e aguardar resposta (até 3 tentativas)
    unsigned char resp_buf[65536];
    struct sockaddr_in from;
    socklen_t from_len;
    ssize_t resp_len = -1;

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        ssize_t sent = sendto(socketfd, query_buf, query_len, 0,
                              (struct sockaddr *)&dest, sizeof(dest));
        if (sent < 0) {
            perror("Erro no sendto");
            continue;           // tenta de novo (se ainda houver tentativa)
        }

        from_len = sizeof(from);
        resp_len = recvfrom(socketfd, resp_buf, sizeof(resp_buf), 0,
                            (struct sockaddr *)&from, &from_len);

        if (resp_len > 0) {
            break;              // resposta recebida: sai do loop
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
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

    // A partir daqui: interpretar o payload DNS
    #if DEBUG
    fprintf(stderr,
            "[DEBUG] Resposta recebida: %zd bytes de %s\n",
            resp_len,
            inet_ntoa(from.sin_addr));
    #endif
    
    // Recebe a resposta, interpreta os bytes e imprime o resultado no formato esperado
    int parse_result = parse_dns_response(resp_buf, resp_len, domain);

    close(socketfd);

    if (parse_result < 0) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
