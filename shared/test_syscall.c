#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define __NR_get_mensagem_original 468
#define __NR_set_mensagem_cifrada 469

int main() {

    const char* mensagem = "TesteMensagem";
    const char* chave    = "dehb83bemd8ha";

    size_t len_mensagem = strlen(mensagem);
    size_t len_chave = strlen(chave);
    char mensagem_cifrada[strlen(mensagem)];
    int retorno;

    printf("\n\nMensagem original: %s\n", mensagem);
    printf("Chave utilizada: %s\n", chave);
    
    retorno = syscall(__NR_set_mensagem_cifrada, mensagem, chave, mensagem_cifrada, len_mensagem , len_chave);

    if (retorno < 0) {
        perror("Erro ao chamar syscall set_mensagem_cifrada");
        return 1;
    }

    printf("\nMensagem cifrada com sucesso.\n");
    printf("Mensagem cifrada (hex): ");
    for (size_t i = 0; i < len_mensagem; i++) {
        printf("%02x ", (unsigned char)mensagem_cifrada[i]);
    }
    printf("\n");
    
    char mensagem_decifrada[strlen(mensagem)];
    retorno = syscall(__NR_get_mensagem_original, mensagem_decifrada, mensagem_cifrada, chave, len_mensagem, len_chave);
    
    if (retorno < 0) {
        perror("Erro ao chamar syscall get_mensagem_original");
        return 1;
    }
    mensagem_decifrada[len_mensagem] = '\0';

    printf("\nMensagem decifrada com sucesso.\n");
    printf("Mensagem decifrada: %s\n", mensagem_decifrada);

    if (strcmp(mensagem_decifrada, mensagem) != 0) {
        fprintf(stderr, "A mensagem decifrada não corresponde à mensagem original.\n\n\n");
        return 1;
    }
    printf("A mensagem decifrada corresponde à mensagem original.\n\n\n");

    return 0;
}