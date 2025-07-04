// SPDX-License-Identifier: GPL-2.0-only
/*
cifra_cesar.c - A module for the classic caesar cipher.
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define DEVICE_NAME "cesar"
#define CLASS_NAME  "cesar_classe"
#define BUFFER_LEN 1024

#define IOCTL_SET_KEY    _IOW('a', 1, int*)
#define IOCTL_ENCRYPT    _IO('a', 2)
#define IOCTL_DECRYPT    _IO('a', 3)

//variaveis do driver
static dev_t dev_num;
static struct class *dev_class;
static struct cdev cesar_cdev;
static char kernel_buffer[BUFFER_LEN];
static int cesar_chave = 3;

//assinaturas das funcoes
static int __init cesar_driver_init(void);
static void __exit cesar_driver_exit(void);
static int cesar_open(struct inode *inode, struct file *file);
static int cesar_release(struct inode *inode, struct file *file);
static ssize_t cesar_read(struct file *filp, char __user *buf, size_t len, loff_t *off);
static ssize_t cesar_write(struct file *filp, const char __user *buf, size_t len, loff_t *off);
static long cesar_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static loff_t cesar_llseek(struct file *file, loff_t offset, int whence); // pra tirar o bug na hora de decifrar

static void cifra_cesar(char *text, int chave) {
    for (int i = 0; text[i] != '\0'; ++i) {
        char ch = text[i];
        if (ch >= 'a' && ch <= 'z') { ch = (ch - 'a' + chave) % 26 + 'a'; }
        else if (ch >= 'A' && ch <= 'Z') { ch = (ch - 'A' + chave) % 26 + 'A'; }
        text[i] = ch;
    }
}

static void decifra_cesar(char *text, int chave) {
    for (int i = 0; text[i] != '\0'; ++i) {
        char ch = text[i];
        if (ch >= 'a' && ch <= 'z') { ch = (ch - 'a' - chave + 26) % 26 + 'a'; }
        else if (ch >= 'A' && ch <= 'Z') { ch = (ch - 'A' - chave + 26) % 26 + 'A'; }
        text[i] = ch;
    }
}


static long cesar_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case IOCTL_SET_KEY:
            if (copy_from_user(&cesar_chave, (int*)arg, sizeof(cesar_chave))) { 
                return -EFAULT; 
            }
            pr_info("A chave é: %d\n", cesar_chave);
            break;
        case IOCTL_ENCRYPT:
            pr_info("Cifrando...\n");
            cifra_cesar(kernel_buffer, cesar_chave);
            break;
        case IOCTL_DECRYPT:
            pr_info("Decifrando...\n");
            decifra_cesar(kernel_buffer, cesar_chave);
            break;
        default:
            return -ENOTTY;
    }
    return 0;
}


static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = cesar_open, // pra arquivo
    .release        = cesar_release, //pra arquivo
    .read           = cesar_read,
    .write          = cesar_write,
    .unlocked_ioctl = cesar_ioctl,
    .llseek         = cesar_llseek, 
};

static int cesar_open(struct inode *inode, struct file *file) {
    pr_info("Device aberto pelo driver César\n"); 
    return 0; 
    }


static int cesar_release(struct inode *inode, struct file *file) { 
    pr_info("Device fechado pelo driver César\n"); 
    return 0; 
}


static loff_t cesar_llseek(struct file *file, loff_t offset, int whence) { // sem essa funcao, da erro no buffer
    loff_t newpos; 
    switch(whence) {
      case 0: /* SEEK_SET */
        newpos = offset;
        break;
      case 1: /* SEEK_CUR */
        newpos = file->f_pos + offset;
        break;
      case 2: /* SEEK_END */
        newpos = strlen(kernel_buffer) + offset;
        break;
      default:
        return -EINVAL;
    }
    if (newpos < 0) 
        return -EINVAL;
    file->f_pos = newpos;
    return newpos;
}

static ssize_t cesar_read(struct file *filp, char __user *buf, size_t len, loff_t *off) {
    int bytes_to_read = strlen(kernel_buffer);
    if (*off >= bytes_to_read) { 
        return 0; 
    }

    if (*off + len > bytes_to_read) { 
        len = bytes_to_read - *off; 
    }

    if (copy_to_user(buf, kernel_buffer + *off, len)) { 
        return -EFAULT; 
    }
    *off += len;
    return len;
}

static ssize_t cesar_write(struct file *filp, const char __user *buf, size_t len, loff_t *off) {
    if (len >= BUFFER_LEN) { 
        return -EINVAL; 
    }
    if (copy_from_user(kernel_buffer, buf, len)) { 
        return -EFAULT; 
    }
    kernel_buffer[len] = '\0';
    pr_info("Escrevi no device: %s\n", kernel_buffer);
    return len;
}

static int __init cesar_driver_init(void) {
    if (alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME) < 0) { 
        return -1; 
    }
    dev_class = class_create(CLASS_NAME);
    if (IS_ERR(dev_class)) { 
        unregister_chrdev_region(dev_num, 1); 
        return PTR_ERR(dev_class); 
    }
    if (IS_ERR(device_create(dev_class, NULL, dev_num, NULL, DEVICE_NAME))) { 
        class_destroy(dev_class); unregister_chrdev_region(dev_num, 1); 
        return -1;
     }
    cdev_init(&cesar_cdev, &fops);
    if (cdev_add(&cesar_cdev, dev_num, 1) < 0) { 
        device_destroy(dev_class, dev_num); class_destroy(dev_class); 
        unregister_chrdev_region(dev_num, 1); 
        return -1; }
    pr_info("Driver Inicializado\n");
    return 0;
}

static void __exit cesar_driver_exit(void) {
    cdev_del(&cesar_cdev);
    device_destroy(dev_class, dev_num);
    class_destroy(dev_class);
    unregister_chrdev_region(dev_num, 1);
    pr_info("Driver fechado\n");
}

module_init(cesar_driver_init);
module_exit(cesar_driver_exit);

MODULE_AUTHOR("Maria Beatriz Moreira, Henrique Parede de Souza, Francisco Vinicius Guedes");
MODULE_DESCRIPTION("Um device driver da cifra de César clássica (k=3)");
MODULE_LICENSE("GPL");