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

int main(int argc, char *argv[]) {
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

    // TODO: Montar o pacote DNS (Header + Question) programaticamente
    // Dica: Usar dns_header_t, gerar ID aleatório, e codificar as flags conforme roteiro.

    // TODO: Loop para enviar a requisição e aguardar resposta (até 3 tentativas)
    
    // TODO: Receber a resposta e interpretar os bytes
    
    // TODO: Imprimir o resultado no formato esperado
    
    close(sockfd);
    return 0;
}
