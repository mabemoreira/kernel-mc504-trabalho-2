#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/printk.h>
#include <linux/gfp.h>
#include <linux/types.h>

SYSCALL_DEFINE5(set_mensagem_cifrada, 
        char __user *, mensagem,
        const char __user *, chave, 
        char __user *, retorno,
        size_t, tamanho_cifrada, 
        size_t, tamanho_chave)
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

   
    for (size_t i = 0; i < tamanho_cifrada; i++) {
        kcifrada[i] = kmensagem[i] ^ kchave[i];
        kmensagem[i] = '#'; // suja a mensagem original
    }

    if (copy_to_user(retorno, kcifrada, tamanho_cifrada) || copy_to_user(mensagem, kmensagem, tamanho_cifrada)) {
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