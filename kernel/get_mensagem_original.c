#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/gfp.h>

SYSCALL_DEFINE5(get_mensagem_original, unsigned char __user *, mensagem, unsigned char __user *, chave, unsigned char __user *, cifrada, unsigned long, tamanho_cifrada, unsigned long, tamanho_chave)
{
    if (tamanho_chave < tamanho_cifrada) {
        printk(KERN_ERR "Erro: chave menor que a mensagem.\n");
        return -EINVAL;
    }

    unsigned char *kcifrada;
    kcifrada = kmalloc(tamanho_cifrada, GFP_KERNEL);
    if (!kcifrada)
        return -ENOMEM;
    if (copy_from_user(kcifrada, cifrada, tamanho_cifrada)) {
        kfree(kcifrada);
        return -EFAULT;
    }

    unsigned char *kchave;
    kchave = kmalloc(tamanho_chave, GFP_KERNEL);
    if (!kchave) {
        kfree(kcifrada);
        return -ENOMEM;
    }
    if (copy_from_user(kchave, chave, tamanho_cifrada)) {
        kfree(kcifrada);
        kfree(kchave);
        return -EFAULT;
    }

    unsigned char *kmensagem;
    kmensagem = kmalloc(tamanho_cifrada, GFP_KERNEL);
    if (!kmensagem) {
        kfree(kcifrada);
        kfree(kchave);
        return -ENOMEM;
    }

    for (size_t i = 0; i < tamanho_cifrada; i++) {
        kmensagem[i] = kcifrada[i] ^ kchave[i];
    }

    if (copy_to_user(mensagem, kmensagem, tamanho_cifrada)) {
        kfree(kcifrada);
        kfree(kchave);
        kfree(kmensagem);
        return -EFAULT;
    }

    kfree(kcifrada);
    kfree(kchave);
    kfree(kmensagem);

    return 0;
}