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

#define RECV_TIMEOUT_SEC 2
#define MAX_ATTEMPTS 3

// Formata o nome de domínio para o padrão do DNS (ex: "unb.br" -> "\x03unb\x02br\x00")
void format_dns_name(unsigned char *dns, const unsigned char *host) {
    int lock = 0, i;
    int host_len = strlen((const char*)host);

    for (i = 0; i <= host_len; i++) {
        if (host[i] == '.' || host[i] == '\0') {
            *dns++ = i - lock;
            for (; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

int build_dns_query(const char *domain, unsigned char *buffer, uint16_t *out_txid) {
    dns_header_t *dns = (dns_header_t *)buffer;

    uint16_t txid = (uint16_t)((rand() & 0xFFFF) ^ ((rand() & 0xFF) << 8));
    if (out_txid) *out_txid = txid;

    dns->id = htons(txid);
    dns->flags = htons(0x0100);
    dns->qdcount = htons(0x0001);
    dns->ancount = htons(0x0000);
    dns->nscount = htons(0x0000);
    dns->arcount = htons(0x0000);

    unsigned char *qname = &buffer[sizeof(dns_header_t)];

    char host[256];
    strncpy(host, domain, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';

    format_dns_name(qname, (unsigned char*)host);

    int qname_len = strlen((const char*)qname) + 1;
    unsigned char *qinfo = qname + qname_len;

    uint16_t qtype = htons(QTYPE_MX);
    memcpy(qinfo, &qtype, sizeof(qtype));
    qinfo += sizeof(qtype);

    uint16_t qclass = htons(QCLASS_IN);
    memcpy(qinfo, &qclass, sizeof(qclass));
    qinfo += sizeof(qclass);

    return (qinfo - buffer);
}

/* 
 * Lê um nome no formato DNS, decodificando os ponteiros de compressão (em que os
 * 2 bits mais significativos são 11, seguidos por um offset de 14 bits apontando 
 * para o trecho do pacote em que o restante do nome se encontra).
 * 
 * Retorna a quantidade de bytes consumidos no pacote original (sem contar os
 * bytes lidos em saltos subsequentes) ou -1 em caso de formato inválido/loop circular.
 */
int read_dns_name(const unsigned char *msg, int msg_len, int offset, char *out, int out_size) {
    int pos = offset;
    int out_pos = 0;
    int consumed = 0;
    int jumped = 0;
    int jumps = 0; // Previne loops infinitos no processamento de ponteiros

    if (offset < 0 || offset >= msg_len || out_size <= 0) return -1;

    while (pos < msg_len) {
        unsigned char len = msg[pos];
        if (len == 0) {
            if (!jumped) consumed++;
            break;
        }

        // Verifica uso de compressão DNS (bits 11xxxxxx)
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= msg_len) return -1;
            
            int pointer = ((msg[pos] & 0x3F) << 8) | msg[pos + 1];
            if (pointer >= msg_len) return -1;

            if (!jumped) consumed += 2;
            
            pos = pointer;
            jumped = 1;
            
            if (++jumps > msg_len) return -1;
            continue;
        }

        if ((len & 0xC0) != 0) return -1;

        pos++;
        if (!jumped) consumed++;

        if (pos + len > msg_len) return -1;

        if (out_pos > 0) {
            if (out_pos >= out_size - 1) return -1;
            out[out_pos++] = '.';
        }

        for (int i = 0; i < len; i++) {
            if (out_pos >= out_size - 1) return -1;
            out[out_pos++] = msg[pos + i];
        }

        pos += len;
        if (!jumped) consumed += len;
    }

    if (pos >= msg_len) return -1;
    out[out_pos] = '\0';
    return consumed;
}

/*
 * Interpreta a resposta DNS pulando corretamente as seções Header e Question,
 * e escaneando a seção de Answer. Filtra o registro MX de menor preferência
 * (maior prioridade, RFC 1035) e imprime o resultado conforme as regras do roteiro.
 */
int parse_dns_response(const unsigned char *response, int response_len, const char *domain, uint16_t expected_txid) {
    if (response_len < (int)sizeof(dns_header_t)) {
        fprintf(stderr, "Resposta DNS invalida.\n");
        return -1;
    }

    const dns_header_t *header = (const dns_header_t *)response;
    uint16_t resp_id = ntohs(header->id);
    
    if (resp_id != expected_txid) {
        fprintf(stderr, "Transaction ID inesperado: esperado 0x%04x, recebido 0x%04x\n", expected_txid, resp_id);
        return -1;
    }

    uint16_t flags = ntohs(header->flags);
    uint16_t qdcount = ntohs(header->qdcount);
    uint16_t ancount = ntohs(header->ancount);
    int rcode = flags & 0x000F;

    if (rcode == 3) {
        printf("Dom\xc3\xadnio %s nao encontrado\n", domain);
        return 0;
    }

    if (rcode != 0) {
        fprintf(stderr, "Erro DNS ao consultar %s (RCODE = %d)\n", domain, rcode);
        return -1;
    }

    int offset = sizeof(dns_header_t);

    for (int i = 0; i < qdcount; i++) {
        char question_name[256];
        int consumed = read_dns_name(response, response_len, offset, question_name, sizeof(question_name));
        
        if (consumed < 0) {
            fprintf(stderr, "Erro ao interpretar a secao Question.\n");
            return -1;
        }

        offset += consumed + 4; // Pula QNAME consumido + QTYPE (2) + QCLASS (2)
        if (offset > response_len) {
            fprintf(stderr, "Resposta DNS truncada na secao Question.\n");
            return -1;
        }
    }

    int mx_found = 0;
    int best_preference = 0x7FFFFFFF;
    char best_mx_name[256] = {0};

    // Percorre os registros RR e salva o MX de maior prioridade (menor preference)
    for (int i = 0; i < ancount; i++) {
        char answer_name[256];
        int consumed = read_dns_name(response, response_len, offset, answer_name, sizeof(answer_name));
        
        if (consumed < 0) {
            fprintf(stderr, "Erro ao interpretar nome da resposta DNS.\n");
            return -1;
        }

        offset += consumed;
        if (offset + 10 > response_len) {
            fprintf(stderr, "Resposta DNS truncada.\n");
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
        
        offset += 4; // TTL
        
        uint16_t rdlength;
        memcpy(&rdlength, response + offset, sizeof(rdlength));
        rdlength = ntohs(rdlength);
        offset += 2;

        if (offset + rdlength > response_len) {
            fprintf(stderr, "RDATA invalido ou resposta DNS truncada.\n");
            return -1;
        }

        if (type == QTYPE_MX && class == QCLASS_IN) {
            if (rdlength < 3) {
                fprintf(stderr, "Registro MX invalido.\n");
                return -1;
            }

            uint16_t preference;
            memcpy(&preference, response + offset, sizeof(preference));
            preference = ntohs(preference);
            
            char mx_name[256];
            if (read_dns_name(response, response_len, offset + 2, mx_name, sizeof(mx_name)) < 0) {
                fprintf(stderr, "Erro ao interpretar servidor MX.\n");
                return -1;
            }

            if (preference < best_preference) {
                best_preference = preference;
                strncpy(best_mx_name, mx_name, sizeof(best_mx_name) - 1);
                best_mx_name[sizeof(best_mx_name) - 1] = '\0';
            }
            mx_found = 1;
        }
        
        // Pula todo o RDATA (tamanho variável) independente do tipo processado acima
        offset += rdlength;
    }

    if (mx_found) {
        printf("%s <> %s\n", domain, best_mx_name);
    } else {
        printf("Dom\xc3\xadnio %s nao possui entrada MX\n", domain);
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    srand(time(NULL));

    if (argc != 3) {
        fprintf(stderr, "Uso: %s <nome_dominio> <ip_servidor_dns>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *domain = argv[1];
    const char *dns_server = argv[2];

    int socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socketfd < 0) {
        perror("Erro ao criar socket");
        exit(EXIT_FAILURE);
    }

    struct timeval tv;
    tv.tv_sec = RECV_TIMEOUT_SEC;
    tv.tv_usec = 0;

    if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
        perror("Erro ao configurar SO_RCVTIMEO");
        close(socketfd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    
    if (inet_pton(AF_INET, dns_server, &dest.sin_addr) <= 0) {
        fprintf(stderr, "IP do servidor invalido: %s\n", dns_server);
        close(socketfd);
        exit(EXIT_FAILURE);
    }

    unsigned char query_buf[65536];
    uint16_t txid = 0;
    int query_len = build_dns_query(domain, query_buf, &txid);

    unsigned char resp_buf[65536];
    ssize_t resp_len = -1;

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        ssize_t sent = sendto(socketfd, query_buf, query_len, 0, (struct sockaddr *)&dest, sizeof(dest));
        if (sent < 0) {
            perror("Erro no sendto");
            continue;
        }

        resp_len = recvfrom(socketfd, resp_buf, sizeof(resp_buf), 0, NULL, NULL);

        if (resp_len > 0) break;

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "Tentativa %d/%d: timeout apos %d segundos.\n", attempt, MAX_ATTEMPTS, RECV_TIMEOUT_SEC);
        } else {
            perror("Erro no recvfrom");
        }
    }

    if (resp_len <= 0) {
        printf("Nao foi possível coletar entrada MX para %s\n", domain);
        close(socketfd);
        return EXIT_FAILURE;
    }

    int parse_result = parse_dns_response(resp_buf, resp_len, domain, txid);
    close(socketfd);

    if (parse_result < 0) return EXIT_FAILURE;
    
    return EXIT_SUCCESS;
}