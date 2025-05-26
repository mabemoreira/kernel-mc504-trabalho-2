#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/printk.h>
#include <linux/gfp.h>
#include <linux/types.h>

SYSCALL_DEFINE5(set_mensagem_cifrada, unsigned char __user *, mensagem,
        unsigned char __user *, chave, unsigned char __user *, cifrada,
        unsigned long, tamanho_cifrada, unsigned long, tamanho_chave)
{

    if (tamanho_chave < tamanho_cifrada) {
        printk(KERN_ERR "Erro: chave menor que a mensagem.\n");
        return -EINVAL;
    }

    unsigned char *kmensagem;
    kmensagem = kmalloc(tamanho_cifrada, GFP_KERNEL);
    if (!kmensagem)
        return -ENOMEM;
    if (copy_from_user(kmensagem, mensagem, tamanho_cifrada)) {
        kfree(kmensagem);
        return -EFAULT;
    }

    unsigned char *kchave;
    kchave = kmalloc(tamanho_chave, GFP_KERNEL);
    if (!kchave) {
        kfree(kmensagem);
        return -ENOMEM;
    }
    if (copy_from_user(kchave, chave, tamanho_chave)) {
        kfree(kmensagem);
        kfree(kchave);
        return -EFAULT;
    }

    unsigned char *kcifrada;
    kcifrada = kmalloc(tamanho_cifrada, GFP_KERNEL);
    if (!kcifrada) {
        kfree(kmensagem);
        kfree(kchave);
        return -ENOMEM;
    }

    // Não precisa copiar de cifrada, apenas gerar o resultado
    for (unsigned long i = 0; i < tamanho_cifrada; i++) {
        kcifrada[i] = kmensagem[i] ^ kchave[i];
    }

    if (copy_to_user(cifrada, kcifrada, tamanho_cifrada)) {
        kfree(kmensagem);
        kfree(kchave);
        kfree(kcifrada);
        return -EFAULT;
    }

    kfree(kmensagem);
    kfree(kchave);
    kfree(kcifrada);

    return 0;
}