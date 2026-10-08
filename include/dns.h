#ifndef DNS_H
#define DNS_H

#include <stdint.h>

/*
 * Estruturas e assinaturas para resolução DNS (RFC 1035)
 */

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed)) dns_header_t;

typedef struct {
    uint16_t qtype;
    uint16_t qclass;
} __attribute__((packed)) dns_question_t;

#define DNS_PORT 53
#define QTYPE_MX 15
#define QCLASS_IN 1

int build_dns_query(const char *domain, unsigned char *buffer, uint16_t *out_txid);
int read_dns_name(const unsigned char *msg, int msg_len, int offset, char *out, int out_size);
int parse_dns_response(const unsigned char *response, int response_len, const char *domain, uint16_t expected_txid);

#endif // DNS_H