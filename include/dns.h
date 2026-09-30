#ifndef DNS_H
#define DNS_H

#include <stdint.h>

/*
 * Estruturas do cabeçalho DNS (RFC 1035)
 * O payload deve ser montado programaticamente.
 */

// Cabeçalho DNS (12 bytes)
typedef struct {
    uint16_t id;       // ID da transação (aleatório)
    uint16_t flags;    // Flags (ex: 0x0100 para requisição recursiva)
    uint16_t qdcount;  // Número de questões (0x0001)
    uint16_t ancount;  // Respostas (0x0000)
    uint16_t nscount;  // Autoridade (0x0000)
    uint16_t arcount;  // Adicional (0x0000)
} __attribute__((packed)) dns_header_t;

// Constantes DNS
#define DNS_PORT 53
#define QTYPE_MX 15
#define QCLASS_IN 1

// Assinatura de funções
int build_dns_query(const char *domain, unsigned char *buffer);
int read_dns_name(const unsigned char *msg, int msg_len, int offset, char *out, int out_size);
int parse_dns_response(const unsigned char *response, int response_len, const char *domain);

#endif // DNS_H
