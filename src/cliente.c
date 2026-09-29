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

// Função auxiliar para formatar o nome de domínio para o padrão do DNS
// Ex: "unb.br" -> "\x03unb\x02br\x00"
void format_dns_name(unsigned char *dns, unsigned char *host) {
    int lock = 0 , i;
    strcat((char*)host,".");
    
    for(i = 0 ; i < strlen((char*)host) ; i++) {
        if(host[i] == '.') {
            *dns++ = i - lock;
            for(; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
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

    // Configuracao do endereco do servidor (struct socketaddr_in)
    struct socketaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(DNS_PORT);
    if (inet_pton(AF_INET, dns_server, &dest.sin_addr) <= 0) {
        fprintf(stderr, "IP do servidor invalido: %s\n", dns_server);
        close(socketfd);
        exit(EXIT_FAILURE);
    }

    // Montagem do pacote DNS (Header + Question) programaticamente
    unsigned char buffer[65536];
    int query_len = build_dns_query(domain, buffer);

    // Loop para enviar a requisicao e aguardar resposta (até 3 tentativas)
    unsigned char resp_buf[65536];
    struct socketaddr_in from;
    socklen_t from_len;
    ssize_t resp_len = -1;

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        ssize_t sent = sendto(socketfd, query_buf, query_len, 0,
                              (struct socketaddr *)&dest, sizeof(dest));
        if (sent < 0) {
            perror("Erro no sendto");
            continue;           // tenta de novo (se ainda houver tentativa)
        }

        from_len = sizeof(from);
        resp_len = recvfrom(socketfd, resp_buf, sizeof(resp_buf), 0,
                            (struct socketaddr *)&from, &from_len);

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
    printf("Resposta recebida: %zd bytes de %s\n",
           resp_len, inet_ntoa(from.sin_addr));
    
    // TODO: Receber a resposta e interpretar os bytes
    
    // TODO: Imprimir o resultado no formato esperado

    close(socketfd);
    return 0;
}
