#include <linux/cdev.h>

#include <linux/percpu.h>

#include <linux/percpu-defs.h>

#include <linux/delay.h>

#include <linux/device.h>

#include <linux/fs.h>

#include <linux/init.h>

#include <linux/kernel.h>

#include <linux/module.h>

#include <linux/slab.h>

#include <linux/uaccess.h>

#include <linux/utsname.h>

#include <linux/sched.h>

#include <linux/mm.h>

#include <linux/ktime.h>

#include <linux/mutex.h>

#include <linux/sysinfo.h>

#include <asm/processor.h>

#include <linux/sched/signal.h>



#define KFETCH_NUM_INFO 6

#define KFETCH_RELEASE   (1 << 0)

#define KFETCH_NUM_CPUS  (1 << 1)

#define KFETCH_CPU_MODEL (1 << 2)

#define KFETCH_MEM       (1 << 3)

#define KFETCH_UPTIME    (1 << 4)

#define KFETCH_NUM_PROCS (1 << 5)

#define KFETCH_FULL_INFO ((1 << KFETCH_NUM_INFO) - 1)

#define SUCCESS 0

#define DEVICE_NAME "kfetch"

#define KFETCH_BUF_SIZE 1024



static int major;

static int info_mask = KFETCH_FULL_INFO;

static char kfetch_buf[KFETCH_BUF_SIZE];

static DEFINE_MUTEX(kfetch_lock);

static struct class *cls;



static int kfetch_open(struct inode *, struct file *);

static int kfetch_release(struct inode *, struct file *);

static ssize_t kfetch_read(struct file *, char __user *, size_t, loff_t *);

static ssize_t kfetch_write(struct file *, const char __user *, size_t, loff_t *);

DEFINE_PER_CPU(unsigned long, process_counts);



static struct file_operations kfetch_fops = {

    .read = kfetch_read,

    .write = kfetch_write,

    .open = kfetch_open,

    .release = kfetch_release,

};

static int __init kfetch_init(void)

{

    major = register_chrdev(0, DEVICE_NAME, &kfetch_fops);

    if (major < 0) {

        pr_alert("Registering char device failed with %d\n", major);

        return major;

    }

    cls = class_create(THIS_MODULE, DEVICE_NAME);

    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

    pr_info("Device created on /dev/%s\n", DEVICE_NAME);

    return 0;

}

int nr_processes(void) {

    int cpu;

    int total = 0;



    for_each_possible_cpu(cpu) {

        total += per_cpu(process_counts, cpu);

    }



    return total;

}

static void update_process_counts(void) {

    struct task_struct *task;

    int cpu;



    for_each_possible_cpu(cpu) {

        per_cpu(process_counts, cpu) = 0;

    }



    for_each_process(task) {

        cpu = task_cpu(task);

        this_cpu_inc(process_counts);

    }

}



static void __exit kfetch_exit(void)

{

    device_destroy(cls, MKDEV(major, 0));

    class_destroy(cls);

    unregister_chrdev(major, DEVICE_NAME);

}



static int kfetch_open(struct inode *inode, struct file *file)

{

    if (!mutex_trylock(&kfetch_lock)) {

        return -EBUSY;

    }

    try_module_get(THIS_MODULE);

    return 0;

}



static int kfetch_release(struct inode *inode, struct file *file)

{

    mutex_unlock(&kfetch_lock);

    module_put(THIS_MODULE);

    return 0;

}

static ssize_t kfetch_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset) {

    char hostname[64];

    struct sysinfo info;

    int len = 0;
    int hostname_len = strlen(utsname()->nodename);



    if (*offset > 0) {

        return 0; // EOF

    }

    char separator[hostname_len + 1];
    memset(separator, '-', hostname_len);
    separator[hostname_len] = '\0';


    // 主機名稱

    snprintf(hostname, sizeof(hostname), "Host: %s\n", utsname()->nodename);

    len += snprintf(kfetch_buf + len, KFETCH_BUF_SIZE - len, "Host: %s\n", utsname()->nodename);
    len += snprintf(kfetch_buf + len, KFETCH_BUF_SIZE - len, "%s\n", separator);



    // 根據 info_mask 選擇性生成資訊

    if (info_mask & KFETCH_RELEASE) {

        len += snprintf(kfetch_buf + len, KFETCH_BUF_SIZE - len, "Kernel: %s\n", utsname()->release);

    }

    if (info_mask & KFETCH_CPU_MODEL) {

        len += snprintf(kfetch_buf + len, KFETCH_BUF_SIZE - len, "CPU Model: %s\n", boot_cpu_data.x86_model_id);

    }

    if (info_mask & KFETCH_NUM_CPUS) {

        int online_cpus = num_online_cpus();

        int total_cpus = nr_cpu_ids;

        len += snprintf(kfetch_buf + len, KFETCH_BUF_SIZE - len, "CPUs: %d / %d\n", online_cpus, total_cpus);

    }

    if (info_mask & KFETCH_MEM) {

        si_meminfo(&info);

        len += snprintf(kfetch_buf + len, KFETCH_BUF_SIZE - len, 

                        "Mem:  %lu MB/ %lu MB\n",

                        info.freeram* info.mem_unit / (1024 * 1024),

                        info.totalram  * info.mem_unit / (1024 * 1024));

    }

    if (info_mask & KFETCH_NUM_PROCS) {

        update_process_counts();

        len += snprintf(kfetch_buf + len, KFETCH_BUF_SIZE - len, "Procs: %d\n", nr_processes());

    }

    if (info_mask & KFETCH_UPTIME) {

        struct timespec64 uptime;

        unsigned long uptime_in_mins;

        ktime_get_boottime_ts64(&uptime);

        uptime_in_mins = uptime.tv_sec / 60;

        len += snprintf(kfetch_buf + len, KFETCH_BUF_SIZE - len, "Uptime: %ld mins\n", uptime_in_mins);

    }

    

    // 附加 ASCII 藝術

    len += snprintf(kfetch_buf + len, KFETCH_BUF_SIZE - len, 

        "        .-.        \n"

        "       (.. |       \n"

        "       <>  |       \n"

        "      / --- \\      \n"

        "     ( |   | )     \n"

        "    |\\_)__(_//|    \n"

        "  <__)------(__>   \n");



    // 緩衝區溢出檢查

    if (len >= KFETCH_BUF_SIZE) {

        pr_alert("Buffer overflow detected\n");

        return -EINVAL;

    }



    // 將生成的內容複製到使用者空間

    if (copy_to_user(buffer, kfetch_buf, len)) {

        return -EFAULT;

    }
    *offset += len;

    return len;

}
static ssize_t kfetch_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset)
{
    int user_mask;

    if (length != sizeof(int)) {
        pr_alert("Invalid mask size\n");
        return -EINVAL;
    }
    if (copy_from_user(&user_mask, buffer, sizeof(int))) {

        pr_alert("Failed to copy data from user\n");

        return -EFAULT;

    }
    if (user_mask < 0 || user_mask > KFETCH_FULL_INFO) {

        pr_alert("Invalid mask value\n");
        return -EINVAL;
    }
    info_mask = user_mask;
    return sizeof(int);

}



module_init(kfetch_init);

module_exit(kfetch_exit);

MODULE_LICENSE("GPL");

MODULE_AUTHOR("Shwan");
