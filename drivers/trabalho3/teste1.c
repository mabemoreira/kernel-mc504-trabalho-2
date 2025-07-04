#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>

#define DEVICE_NAME "caesar"
#define MAJOR_NUM 100
#define IOCTL_ENCRYPT _IO(MAJOR_NUM, 0)
#define IOCTL_DECRYPT _IO(MAJOR_NUM, 1)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Você");
MODULE_DESCRIPTION("Driver de cifra de César");

#define BUFFER_SIZE 1024
static char texto[BUFFER_SIZE] = {0};

static void cifra_cesar(char *str, int shift) {
    int i = 0;
    char c;

    while ((c = str[i]) != '\0') {
        if (c >= 'a' && c <= 'z')
            str[i] = 'a' + (c - 'a' + shift + 26) % 26;
        else if (c >= 'A' && c <= 'Z')
            str[i] = 'A' + (c - 'A' + shift + 26) % 26;
        i++;
    }
}

static ssize_t device_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    int bytes;
    if (*offset > 0) return 0;

    bytes = strlen(texto) + 1;
    if (copy_to_user(buffer, texto, bytes)) return -EFAULT;

    *offset += bytes;
    return bytes;
}

static ssize_t device_write(struct file *filep, const char *buffer, size_t length, loff_t *offset) {
    if (length >= BUFFER_SIZE) return -EINVAL;

    if (copy_from_user(texto, buffer, length)) return -EFAULT;

    texto[length] = '\0';
    return length;
}

static long device_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case IOCTL_ENCRYPT:
            cifra_cesar(texto, 3);
            break;
        case IOCTL_DECRYPT:
            cifra_cesar(texto, -3);
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

static struct file_operations fops = {
    .read = device_read,
    .write = device_write,
    .unlocked_ioctl = device_ioctl,
};

static int __init caesar_init(void) {
    int ret = register_chrdev(MAJOR_NUM, DEVICE_NAME, &fops);
    if (ret < 0) {
        printk(KERN_ALERT "Falha ao registrar o driver\n");
        return ret;
    }
    printk(KERN_INFO "Driver Caesar carregado com sucesso\n");
    return 0;
}

static void __exit caesar_exit(void) {
    unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
    printk(KERN_INFO "Driver Caesar descarregado\n");
}

module_init(caesar_init);
module_exit(caesar_exit);
