#ifndef DNS_H
#define DNS_H

#include <stdint.h>

/*
 * Estruturas do cabeçalho DNS (RFC 1035)
*/

// Cabeçalho DNS (12 bytes)
typedef struct {
    uint16_t id;       // ID da transação (Transaction ID,aleatório)
    uint16_t flags;    // Flags (0x0100, para indicar requisição recursiva)
    uint16_t qdcount;  // Número de questões (0x0001)
    uint16_t ancount;  // Respostas (Answer RRs, 0x0000)
    uint16_t nscount;  // Autoridade (Authority RRs, 0x0000)
    uint16_t arcount;  // Adicional (Additional RRs, 0x0000)
} __attribute__((packed)) dns_header_t;

// Estrutura para os campos fixos da Question (após o QNAME)
typedef struct {
    uint16_t qtype;
    uint16_t qclass;
} __attribute__((packed)) dns_question_t;

// Constantes DNS
#define DNS_PORT 53
#define QTYPE_MX 15 // tipo de consulta MX
#define QCLASS_IN 1 // classe de consulta IN (Internet)

// Assinatura de funções
// build_dns_query agora devolve também o Transaction ID gerado (para ser conferido na resposta)
int build_dns_query(const char *domain, unsigned char *buffer, uint16_t *out_txid);
int read_dns_name(const unsigned char *msg, int msg_len, int offset, char *out, int out_size);
// parse_dns_response agora recebe o Transaction ID esperado para validar a resposta
int parse_dns_response(const unsigned char *response, int response_len,
                       const char *domain, uint16_t expected_txid);

#endif // DNS_H