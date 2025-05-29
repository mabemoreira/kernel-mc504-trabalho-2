#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/printk.h>
#include <linux/gfp.h>
#include <linux/types.h>

SYSCALL_DEFINE5(get_mensagem_original, 
		char __user *, retorno, 
		char __user *, mensagem_cifrada,
		const char __user *, chave,
		size_t, tamanho_cifrada,
		size_t, tamanho_chave)
{
	if (tamanho_chave < tamanho_cifrada) {
		printk(KERN_ERR "Erro: chave menor que a mensagem.\n");
		return -EINVAL;
	}

	unsigned char *kcifrada;
	kcifrada = kmalloc(tamanho_cifrada, GFP_KERNEL);
	if (!kcifrada)
		return -ENOMEM;
	if (copy_from_user(kcifrada, mensagem_cifrada, tamanho_cifrada)) {
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

	unsigned char *kdecifrada;
	kdecifrada = kmalloc(tamanho_cifrada, GFP_KERNEL);
	if (!kdecifrada) {
		kfree(kcifrada);
		kfree(kchave);
		return -ENOMEM;
	}

	size_t i;
	for (i = 0; i < tamanho_cifrada; i++) {
		kdecifrada[i] = kcifrada[i] ^ kchave[i];
	}
	

	if (copy_to_user(retorno, kdecifrada, tamanho_cifrada)) {
		kfree(kcifrada);
		kfree(kchave);
		kfree(kdecifrada);
		return -EFAULT;
	}

	kfree(kcifrada);
	kfree(kchave);
	kfree(kdecifrada);

	return 0;
}