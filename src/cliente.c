#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

#include "dns.h"

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

    // TODO: Criar socket UDP
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("Erro ao criar socket");
        exit(EXIT_FAILURE);
    }

    // Configura tempo limite (timeout) de 2 segundos para o socket
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // TODO: Configurar endereço do servidor (struct sockaddr_in)
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, dns_server, &dest.sin_addr) <= 0) {
        perror("IP do servidor invalido");
        exit(EXIT_FAILURE);
    }

    // Montagem do pacote DNS (Header + Question) programaticamente
    unsigned char buffer[65536];
    int query_len = build_dns_query(domain, buffer);

    // TODO: Loop para enviar a requisição e aguardar resposta (até 3 tentativas)
    
    // TODO: Receber a resposta e interpretar os bytes
    
    // TODO: Imprimir o resultado no formato esperado
    
    close(sockfd);
    return 0;
}
