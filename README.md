# Linux Project 2 Write Up

{%hackmd iaeIZ7VVT223x4UqDsJevQ %}

## Syscall

```c=
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <asm/errno.h>
#include <asm/io.h>

#define MAX_BUF_SIZE 128

enum MODE {
    BY_SEGMENT = 0,
    BY_VIRTUAL_ADDRESS = 1,
};

struct Segment {
    unsigned long int start_addr;
    unsigned long int end_addr;
    char seg_name[MAX_BUF_SIZE];
    char lib_name[MAX_BUF_SIZE];
};

struct ProcessSegments {
    pid_t pid;
    struct Segment code_seg;
    struct Segment data_seg;
    struct Segment heap_seg;
    struct Segment stack_seg;
    struct Segment mmap_segs[MAX_BUF_SIZE];
    int mmap_seg_count;
};

struct AddrInfo {
    unsigned long int virt_addr;
    unsigned long int phys_addr;
};

struct ProcessSegments* get_segments(void *__user des_addr) {
    struct ProcessSegments* process_segments;
    struct task_struct *task;
    struct vm_area_struct* current_vm_area;
    int ret;
    int seg_count = 0;

    process_segments = kmalloc(sizeof(struct ProcessSegments), GFP_KERNEL);
    
    ret = copy_from_user(process_segments, des_addr, sizeof(struct ProcessSegments));
    if(ret != 0) {
        printk(KERN_ALERT "copy_from_user failed\n");
        return (void *) NULL;
    }

    task = find_task_by_vpid(process_segments->pid);
    if (!task) {
        return (void *) NULL;
    }

    process_segments->code_seg.start_addr = (unsigned long int) task->mm->start_code;
    process_segments->code_seg.end_addr = (unsigned long int) task->mm->end_code;
    strcpy(process_segments->code_seg.seg_name, "code_seg");
    strcpy(process_segments->code_seg.lib_name, "NULL");

    process_segments->data_seg.start_addr = (unsigned long int) task->mm->start_data;
    process_segments->data_seg.end_addr = (unsigned long int) task->mm->end_data;
    strcpy(process_segments->data_seg.seg_name, "data_seg");
    strcpy(process_segments->data_seg.lib_name, "NULL");

    process_segments->heap_seg.start_addr = (unsigned long int) task->mm->start_brk;
    process_segments->heap_seg.end_addr = (unsigned long int) task->mm->brk;
    strcpy(process_segments->heap_seg.seg_name, "heap_seg");
    strcpy(process_segments->heap_seg.lib_name, "NULL");

    process_segments->stack_seg.start_addr = (unsigned long int) task->mm->start_stack;
    process_segments->stack_seg.end_addr = (unsigned long int) (task->mm->start_stack + task->mm->stack_vm);
    strcpy(process_segments->stack_seg.seg_name, "stack_seg");
    strcpy(process_segments->stack_seg.lib_name, "NULL");

    for (current_vm_area = task->mm->mmap; current_vm_area; current_vm_area = current_vm_area->vm_next)
    {
        process_segments->mmap_segs[seg_count].start_addr = (unsigned long int) current_vm_area->vm_start;
        process_segments->mmap_segs[seg_count].end_addr = (unsigned long int) current_vm_area->vm_end;
        strcpy(process_segments->mmap_segs[seg_count].seg_name, "seg_TBD");

        if (current_vm_area->vm_file) {
            strcpy(process_segments->mmap_segs[seg_count].seg_name, "shared_lib");
            strcpy(process_segments->mmap_segs[seg_count].lib_name, current_vm_area->vm_file->f_path.dentry->d_name.name);
        } else {
            strcpy(process_segments->mmap_segs[seg_count].lib_name, "NULL");
        }

        seg_count++;
    }

    process_segments->mmap_seg_count = seg_count;

    return process_segments;
}

struct AddrInfo* get_phys_addr(void *__user des_addr) {
    struct AddrInfo* addr_info;
    int ret;

    addr_info = kmalloc(sizeof(struct AddrInfo), GFP_KERNEL);
    
    ret = copy_from_user(addr_info, des_addr, sizeof(struct AddrInfo));
    if (ret != 0) {
        return (void *) NULL;
    }

    addr_info->phys_addr = (unsigned long int) virt_to_phys((volatile void*) addr_info->virt_addr);

    return addr_info;
}

SYSCALL_DEFINE2(get_address, int, mode, void *__user, des_addr) {
    int ret = 0;

    switch ((enum MODE) mode) {
        case BY_SEGMENT: {
            struct ProcessSegments* process_segments;

            process_segments = get_segments(des_addr);
            ret = copy_to_user(des_addr, process_segments, sizeof(struct ProcessSegments));
            
            break;
        }
        case BY_VIRTUAL_ADDRESS: {
            struct AddrInfo* addr_info;

            addr_info = get_phys_addr(des_addr);
            ret = copy_to_user(des_addr, addr_info, sizeof(struct AddrInfo));
            
            break;
        }
        default:
            return -EINVAL;
    }

    return ret;
}
```

### virt_to_phys

- virt_to_phys 擴展 ([source](https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/page_64.h#L18))

```c=
#define _AC(X,Y)  (X##Y)
#define UL(x)    (_UL(x))
#define _UL(x)    (_AC(x, UL))
#define __START_KERNEL_map  _AC(0xffffffff80000000, UL)
#define PAGE_OFFSET_BASE_L4  _AC(0xffff888000000000, UL)

unsigned long virt_to_phys(unsigned long x)
{
  unsigned long y = x - __START_KERNEL_map;

  /* use the carry flag to determine if x was < __START_KERNEL_map */
  x = y + ((x > y) ? phys_base : (__START_KERNEL_map - PAGE_OFFSET));

  return x;
}
```

> 一開始從 [virt_to_phy](https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/io.h#L133)發現了__pa這東西，然後繼續search下去找__pa在做啥，接著在這[define __pa(x)](https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/page.h#L42)發現了它的定義，因為又引用了一個新的function名```__phys_addr((unsigned long)(x))``` ，所以我們繼續trace下去，並在這裡發現它的定義 [#define __phys_addr(x)](https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/page_64.h#L32)，到這裡發現了有趣的function名```__phys_addr_nodebug(x)```，理所當然地繼續trace下去，link在這裡[__phys_addr_nodebug(x)](https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/page_64.h#L18)，裡面有一個 ```__START_KERNEL_map```，它的定義我寫在下面，而```__START_KERNEL_map```裡定義的_AC在最後是這樣定義的，把兩個string連在一起，中間的運算符號是字串連接operator(##)
> 因為當初在 kernel module 沒辦法直接用 `<asm/io.h>`，因次我們還自己 implement 了 `virt_to_phys` 一次！

--------------------------------------------------------------------

> 後來經提點後回去review了一次，virt_to_phys只能用在kmalloc的address，所以需要的應該是另一個需要用到page_table的function，所以回去找了之前用到的另一個function ```virt_to_page```定義在這[virt_to_page](https://elixir.bootlin.com/linux/latest/source/arch/sparc/include/asm/page_64.h#L152)會return一個pointer前提是virt_addr_valid要先回傳true值，然後透過pfn_to_page傳，但是__pfn_to_page會根據define的不同來進行轉換(三種放在下面)，然後在CONFIG_SPARSEMEM的情況下會將__pfn丟進去__pfn_to_section和__section_mem_map_addr兩個function然後再加上一個__pfn，中間的過程在下ㄇㄧㄢ，然後繼續trace下去到page_to_phys

```c=
#define virt_to_page(kaddr)  pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)

/* ----------------------pfn_to_page 的擴展----------------------*/

#define pfn_to_page __pfn_to_page

// or

#define pfn_to_page(pfn) (void *)((pfn) * PAGE_SIZE)

/* ----------------------__pfn_to_page 的擴展----------------------*/

#if defined(CONFIG_FLATMEM) => #define __pfn_to_page(pfn) (mem_map + ((pfn)-ARCH_PFN_OFFSET))

#elif defined(CONFIG_SPARSEMEM_VMEMMAP) => #define __pfn_to_page(pfn) (vmemmap + (pfn))

#elif defined(CONFIG_SPARSEMEM) =>  
#define __pfn_to_page(pfn)
({
    unsigned long __pfn = (pfn);
    struct mem_section *__sec = __pfn_to_section(__pfn);
    __section_mem_map_addr(__sec) + __pfn;
})

/* ----------------------__pfn_to_section 的擴展----------------------*/


static inline struct mem_section *__pfn_to_section(unsigned long pfn)
{
  return __nr_to_section(pfn_to_section_nr(pfn));
}

/* ----------------------pfn_to_section_nr 的擴展----------------------*/

static inline unsigned long pfn_to_section_nr(unsigned long pfn)
{
  return pfn >> PFN_SECTION_SHIFT;
}

#define PFN_SECTION_SHIFT  (SECTION_SIZE_BITS - PAGE_SHIFT)


/* ----------------------__section_mem_map_addr 的擴展----------------------*/

static inline struct page *__section_mem_map_addr(struct mem_section *section)
{
  unsigned long map = section->section_mem_map;
  map &= SECTION_MAP_MASK;
  return (struct page *)map;
}

/* ----------------------__nr_to_section 的擴展----------------------*/

static inline struct mem_section *__nr_to_section(unsigned long nr)
{
#ifdef CONFIG_SPARSEMEM_EXTREME
  if (!mem_section)
    return NULL;
#endif
  if (!mem_section[SECTION_NR_TO_ROOT(nr)])
    return NULL;
  return &mem_section[SECTION_NR_TO_ROOT(nr)][nr & SECTION_ROOT_MASK];
}

#define SECTION_NR_TO_ROOT(sec) ((sec) / SECTIONS_PER_ROOT)

#ifdef CONFIG_SPARSEMEM_EXTREME
    #define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#else
    #define SECTIONS_PER_ROOT 1
#endif

#define PAGE_SIZE    (_AC(1,UL) << PAGE_SHIFT)
```

> 取得page之後使用 `page_to_phys` 取得 physical memory

```c=
#define page_to_phys(page)    ((dma_addr_t)page_to_pfn(page) << PAGE_SHIFT)

/* ----------------------page_to_pfn 的擴展----------------------*/

#define page_to_pfn __page_to_pfn

// or

#define page_to_pfn(page) ((unsigned long)(page) / PAGE_SIZE)

/* ----------------------__page_to_pfn 的擴展----------------------*/

#if defined(CONFIG_FLATMEM) => #define __pfn_to_page(pfn) (mem_map + ((pfn) - ARCH_PFN_OFFSET))

#elif defined(CONFIG_SPARSEMEM_VMEMMAP) => #define __page_to_pfn(page) (unsigned long)((page) - vmemmap)

#elif defined(CONFIG_SPARSEMEM) =>  
#define __page_to_pfn(pg)
({ const struct page *__pg = (pg);
 int __sec = page_to_section(__pg);
 (unsigned long)(__pg - __section_mem_map_addr(__nr_to_section(__sec)));
})

/* ----------------------page_to_section 的擴展----------------------*/

static inline unsigned long page_to_section(const struct page *page)
{
 return (page->flags >> SECTIONS_PGSHIFT) & SECTIONS_MASK;
}
#endif

/* ----------------------__section_mem_map_addr 的擴展----------------------*/

static inline struct page *__section_mem_map_addr(struct mem_section *section)
{
 unsigned long map = section->section_mem_map;
 map &= SECTION_MAP_MASK;
 return (struct page *)map;
}

/* ----------------------__nr_to_section 的擴展----------------------*/

static inline struct mem_section *__nr_to_section(unsigned long nr)
{
#ifdef CONFIG_SPARSEMEM_EXTREME
  if (!mem_section)
    return NULL;
#endif
  if (!mem_section[SECTION_NR_TO_ROOT(nr)])
    return NULL;
  return &mem_section[SECTION_NR_TO_ROOT(nr)][nr & SECTION_ROOT_MASK];
}
```

## Question 1

### User Space Test Code 1

```c=
#include <syscall.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

int shared_var = 0;
__thread int tls_var = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

#define __NR_get_address 449
#define MAX_BUF_SIZE 128

enum MODE {
    BY_SEGMENT = 0,
    BY_VIRTUAL_ADDRESS = 1,
};

struct Segment {
    unsigned long int start_addr;
    unsigned long int end_addr;
    char seg_name[MAX_BUF_SIZE];
    char lib_name[MAX_BUF_SIZE];
};

struct ProcessSegments {
    pid_t pid;
    struct Segment code_seg;
    struct Segment data_seg;
    struct Segment heap_seg;
    struct Segment stack_seg;
    struct Segment mmap_segs[MAX_BUF_SIZE];
    int mmap_seg_count;
};

struct AddrInfo {
    unsigned long int virt_addr;
    unsigned long int phys_addr;
};

unsigned long int get_phys_addr(unsigned long int virt_addr) {
    struct AddrInfo addr_info;
    addr_info.virt_addr = virt_addr;

    syscall(__NR_get_address, BY_VIRTUAL_ADDRESS, (void *) &addr_info);
    
    return addr_info.phys_addr;
}

void get_thread_seg(){
    // lock the thread only one thread can ececute
    pthread_mutex_lock(&mutex);

    printf("\n--- THREAD START ---\n");
 
    struct ProcessSegments thread_segs;
    
    // at here to call syscall to get thread segemnet
    // get thread tid
    int tid = syscall(__NR_gettid);
    thread_segs.pid = tid;
    
    // call get_address syscall
    syscall(__NR_get_address, BY_SEGMENT, (void *) &thread_segs);
    printf("%s: %lx-%lx (%lx-%lx)\n", thread_segs.code_seg.seg_name, thread_segs.code_seg.start_addr, thread_segs.code_seg.end_addr, get_phys_addr(thread_segs.code_seg.start_addr), get_phys_addr(thread_segs.code_seg.end_addr));
    printf("%s: %lx-%lx (%lx-%lx)\n", thread_segs.data_seg.seg_name, thread_segs.data_seg.start_addr, thread_segs.data_seg.end_addr, get_phys_addr(thread_segs.data_seg.start_addr), get_phys_addr(thread_segs.data_seg.end_addr));
    printf("%s: %lx-%lx (%lx-%lx)\n", thread_segs.heap_seg.seg_name, thread_segs.heap_seg.start_addr, thread_segs.heap_seg.end_addr, get_phys_addr(thread_segs.heap_seg.start_addr), get_phys_addr(thread_segs.heap_seg.end_addr));
    printf("%s: %lx-%lx (%lx-%lx)\n", thread_segs.stack_seg.seg_name, thread_segs.stack_seg.start_addr, thread_segs.stack_seg.end_addr, get_phys_addr(thread_segs.stack_seg.start_addr), get_phys_addr(thread_segs.stack_seg.end_addr));
    
    for (int i = 0; i < thread_segs.mmap_seg_count; i++) {
        if (strcmp(thread_segs.mmap_segs[i].lib_name, "NULL") != 0) {
            printf("%s (%s): %lx-%lx (%lx-%lx)\n", thread_segs.mmap_segs[i].seg_name, thread_segs.mmap_segs[i].lib_name, thread_segs.mmap_segs[i].start_addr, thread_segs.mmap_segs[i].end_addr, get_phys_addr(thread_segs.mmap_segs[i].start_addr), get_phys_addr(thread_segs.mmap_segs[i].end_addr));
        } else {            
            printf("%s: %lx-%lx (%lx-%lx)\n", thread_segs.mmap_segs[i].seg_name, thread_segs.mmap_segs[i].start_addr, thread_segs.mmap_segs[i].end_addr, get_phys_addr(thread_segs.mmap_segs[i].start_addr), get_phys_addr(thread_segs.mmap_segs[i].end_addr));
        }
    }

    // print the shared var address
    printf("shared_var: %lx (%lx)\n", (unsigned long int) &shared_var, get_phys_addr((unsigned long int) &shared_var));

    // print the TLS var address
    printf("TLS_addr: %lx (%lx)\n", (unsigned long int) &tls_var, get_phys_addr((unsigned long int) &tls_var));

    int local_var = 0;
    printf("local_var_addr: %lx (%lx)\n", (unsigned long int) &local_var, get_phys_addr((unsigned long int) &local_var));

    // unlock
    pthread_mutex_unlock(&mutex);
 
    return;
}


int main() {
    pthread_t pid_1,pid_2,pid_3;
    struct ProcessSegments process_segs;
    
 pthread_create(&pid_1, NULL, (void * (*)(void *)) get_thread_seg, NULL);  
    pthread_create(&pid_2, NULL, (void * (*)(void *)) get_thread_seg, NULL);
    pthread_create(&pid_3, NULL, (void * (*)(void *)) get_thread_seg, NULL);
    
    pthread_join(pid_1, NULL);
 pthread_join(pid_2, NULL);
    pthread_join(pid_3, NULL);

    return 0;
}

```

### Test Command 1

```c=
gcc -no-pie -o get_address_test.o get_address_test.c -lpthread && ./get_address_test.o
```

### 實驗成果 1

#### THREAD 1

```bash=
--- THREAD START ---
code_seg: 401000-401965 (770640401000-770640401965)
data_seg: 403e00-404070 (770640403e00-770640404070)
heap_seg: 13dd000-13fe000 (7706413dd000-7706413fe000)
stack_seg: 7ffe14e6db80-7ffe14e6dba1 (f70454e6db80-f70454e6dba1)
shared_lib (get_address_test.o): 400000-401000 (770640400000-770640401000)
shared_lib (get_address_test.o): 401000-402000 (770640401000-770640402000)
shared_lib (get_address_test.o): 402000-403000 (770640402000-770640403000)
shared_lib (get_address_test.o): 403000-404000 (770640403000-770640404000)
shared_lib (get_address_test.o): 404000-405000 (770640404000-770640405000)
seg_TBD: 13dd000-13fe000 (7706413dd000-7706413fe000)
seg_TBD: 7f8be8000000-7f8be8021000 (f69228000000-f69228021000)
seg_TBD: 7f8be8021000-7f8bec000000 (f69228021000-f6922c000000)
seg_TBD: 7f8bec88e000-7f8bed090000 (f6922c88e000-f6922d090000)
seg_TBD: 7f8bed090000-7f8bed890000 (f6922d090000-f6922d890000)
seg_TBD: 7f8bed890000-7f8bed891000 (f6922d890000-f6922d891000)
seg_TBD: 7f8bed891000-7f8bee094000 (f6922d891000-f6922e094000)
shared_lib (libc-2.31.so): 7f8bee094000-7f8bee0b9000 (f6922e094000-f6922e0b9000)
shared_lib (libc-2.31.so): 7f8bee0b9000-7f8bee231000 (f6922e0b9000-f6922e231000)
shared_lib (libc-2.31.so): 7f8bee231000-7f8bee27b000 (f6922e231000-f6922e27b000)
shared_lib (libc-2.31.so): 7f8bee27b000-7f8bee27c000 (f6922e27b000-f6922e27c000)
shared_lib (libc-2.31.so): 7f8bee27c000-7f8bee27f000 (f6922e27c000-f6922e27f000)
shared_lib (libc-2.31.so): 7f8bee27f000-7f8bee282000 (f6922e27f000-f6922e282000)
seg_TBD: 7f8bee282000-7f8bee286000 (f6922e282000-f6922e286000)
shared_lib (libpthread-2.31.so): 7f8bee286000-7f8bee28d000 (f6922e286000-f6922e28d000)
shared_lib (libpthread-2.31.so): 7f8bee28d000-7f8bee29e000 (f6922e28d000-f6922e29e000)
shared_lib (libpthread-2.31.so): 7f8bee29e000-7f8bee2a3000 (f6922e29e000-f6922e2a3000)
shared_lib (libpthread-2.31.so): 7f8bee2a3000-7f8bee2a4000 (f6922e2a3000-f6922e2a4000)
shared_lib (libpthread-2.31.so): 7f8bee2a4000-7f8bee2a5000 (f6922e2a4000-f6922e2a5000)
seg_TBD: 7f8bee2a5000-7f8bee2ab000 (f6922e2a5000-f6922e2ab000)
shared_lib (ld-2.31.so): 7f8bee2ba000-7f8bee2bb000 (f6922e2ba000-f6922e2bb000)
shared_lib (ld-2.31.so): 7f8bee2bb000-7f8bee2de000 (f6922e2bb000-f6922e2de000)
shared_lib (ld-2.31.so): 7f8bee2de000-7f8bee2e6000 (f6922e2de000-f6922e2e6000)
shared_lib (ld-2.31.so): 7f8bee2e7000-7f8bee2e8000 (f6922e2e7000-f6922e2e8000)
shared_lib (ld-2.31.so): 7f8bee2e8000-7f8bee2e9000 (f6922e2e8000-f6922e2e9000)
seg_TBD: 7f8bee2e9000-7f8bee2ea000 (f6922e2e9000-f6922e2ea000)
seg_TBD: 7ffe14e4e000-7ffe14e6f000 (f70454e4e000-f70454e6f000)
seg_TBD: 7ffe14ec0000-7ffe14ec4000 (f70454ec0000-f70454ec4000)
seg_TBD: 7ffe14ec4000-7ffe14ec6000 (f70454ec4000-f70454ec6000)
shared_var: 4040a0 (7706404040a0)
TLS_addr: 7f8bee0906fc (f6922e0906fc)
local_var_addr: 7f8bee087274 (f6922e087274)
```

#### THREAD 2

```bash=
--- THREAD START ---
code_seg: 401000-401965 (770640401000-770640401965)
data_seg: 403e00-404070 (770640403e00-770640404070)
heap_seg: 13dd000-13fe000 (7706413dd000-7706413fe000)
stack_seg: 7ffe14e6db80-7ffe14e6dba1 (f70454e6db80-f70454e6dba1)
shared_lib (get_address_test.o): 400000-401000 (770640400000-770640401000)
shared_lib (get_address_test.o): 401000-402000 (770640401000-770640402000)
shared_lib (get_address_test.o): 402000-403000 (770640402000-770640403000)
shared_lib (get_address_test.o): 403000-404000 (770640403000-770640404000)
shared_lib (get_address_test.o): 404000-405000 (770640404000-770640405000)
seg_TBD: 13dd000-13fe000 (7706413dd000-7706413fe000)
seg_TBD: 7f8be8000000-7f8be8021000 (f69228000000-f69228021000)
seg_TBD: 7f8be8021000-7f8bec000000 (f69228021000-f6922c000000)
seg_TBD: 7f8bec88e000-7f8bec88f000 (f6922c88e000-f6922c88f000)
seg_TBD: 7f8bec88f000-7f8bed08f000 (f6922c88f000-f6922d08f000)
seg_TBD: 7f8bed08f000-7f8bed090000 (f6922d08f000-f6922d090000)
seg_TBD: 7f8bed090000-7f8bed890000 (f6922d090000-f6922d890000)
seg_TBD: 7f8bed890000-7f8bed891000 (f6922d890000-f6922d891000)
seg_TBD: 7f8bed891000-7f8bee094000 (f6922d891000-f6922e094000)
shared_lib (libc-2.31.so): 7f8bee094000-7f8bee0b9000 (f6922e094000-f6922e0b9000)
shared_lib (libc-2.31.so): 7f8bee0b9000-7f8bee231000 (f6922e0b9000-f6922e231000)
shared_lib (libc-2.31.so): 7f8bee231000-7f8bee27b000 (f6922e231000-f6922e27b000)
shared_lib (libc-2.31.so): 7f8bee27b000-7f8bee27c000 (f6922e27b000-f6922e27c000)
shared_lib (libc-2.31.so): 7f8bee27c000-7f8bee27f000 (f6922e27c000-f6922e27f000)
shared_lib (libc-2.31.so): 7f8bee27f000-7f8bee282000 (f6922e27f000-f6922e282000)
seg_TBD: 7f8bee282000-7f8bee286000 (f6922e282000-f6922e286000)
shared_lib (libpthread-2.31.so): 7f8bee286000-7f8bee28d000 (f6922e286000-f6922e28d000)
shared_lib (libpthread-2.31.so): 7f8bee28d000-7f8bee29e000 (f6922e28d000-f6922e29e000)
shared_lib (libpthread-2.31.so): 7f8bee29e000-7f8bee2a3000 (f6922e29e000-f6922e2a3000)
shared_lib (libpthread-2.31.so): 7f8bee2a3000-7f8bee2a4000 (f6922e2a3000-f6922e2a4000)
shared_lib (libpthread-2.31.so): 7f8bee2a4000-7f8bee2a5000 (f6922e2a4000-f6922e2a5000)
seg_TBD: 7f8bee2a5000-7f8bee2ab000 (f6922e2a5000-f6922e2ab000)
shared_lib (ld-2.31.so): 7f8bee2ba000-7f8bee2bb000 (f6922e2ba000-f6922e2bb000)
shared_lib (ld-2.31.so): 7f8bee2bb000-7f8bee2de000 (f6922e2bb000-f6922e2de000)
shared_lib (ld-2.31.so): 7f8bee2de000-7f8bee2e6000 (f6922e2de000-f6922e2e6000)
shared_lib (ld-2.31.so): 7f8bee2e7000-7f8bee2e8000 (f6922e2e7000-f6922e2e8000)
shared_lib (ld-2.31.so): 7f8bee2e8000-7f8bee2e9000 (f6922e2e8000-f6922e2e9000)
seg_TBD: 7f8bee2e9000-7f8bee2ea000 (f6922e2e9000-f6922e2ea000)
seg_TBD: 7ffe14e4e000-7ffe14e6f000 (f70454e4e000-f70454e6f000)
seg_TBD: 7ffe14ec0000-7ffe14ec4000 (f70454ec0000-f70454ec4000)
seg_TBD: 7ffe14ec4000-7ffe14ec6000 (f70454ec4000-f70454ec6000)
shared_var: 4040a0 (7706404040a0)
TLS_addr: 7f8bed88f6fc (f6922d88f6fc)
local_var_addr: 7f8bed886274 (f6922d886274)
```

#### THREAD 3

```bash=
--- THREAD START ---
code_seg: 401000-401965 (770640401000-770640401965)
data_seg: 403e00-404070 (770640403e00-770640404070)
heap_seg: 13dd000-13fe000 (7706413dd000-7706413fe000)
stack_seg: 7ffe14e6db80-7ffe14e6dba1 (f70454e6db80-f70454e6dba1)
shared_lib (get_address_test.o): 400000-401000 (770640400000-770640401000)
shared_lib (get_address_test.o): 401000-402000 (770640401000-770640402000)
shared_lib (get_address_test.o): 402000-403000 (770640402000-770640403000)
shared_lib (get_address_test.o): 403000-404000 (770640403000-770640404000)
shared_lib (get_address_test.o): 404000-405000 (770640404000-770640405000)
seg_TBD: 13dd000-13fe000 (7706413dd000-7706413fe000)
seg_TBD: 7f8be8000000-7f8be8021000 (f69228000000-f69228021000)
seg_TBD: 7f8be8021000-7f8bec000000 (f69228021000-f6922c000000)
seg_TBD: 7f8bec88e000-7f8bec88f000 (f6922c88e000-f6922c88f000)
seg_TBD: 7f8bec88f000-7f8bed08f000 (f6922c88f000-f6922d08f000)
seg_TBD: 7f8bed08f000-7f8bed090000 (f6922d08f000-f6922d090000)
seg_TBD: 7f8bed090000-7f8bed890000 (f6922d090000-f6922d890000)
seg_TBD: 7f8bed890000-7f8bed891000 (f6922d890000-f6922d891000)
seg_TBD: 7f8bed891000-7f8bee094000 (f6922d891000-f6922e094000)
shared_lib (libc-2.31.so): 7f8bee094000-7f8bee0b9000 (f6922e094000-f6922e0b9000)
shared_lib (libc-2.31.so): 7f8bee0b9000-7f8bee231000 (f6922e0b9000-f6922e231000)
shared_lib (libc-2.31.so): 7f8bee231000-7f8bee27b000 (f6922e231000-f6922e27b000)
shared_lib (libc-2.31.so): 7f8bee27b000-7f8bee27c000 (f6922e27b000-f6922e27c000)
shared_lib (libc-2.31.so): 7f8bee27c000-7f8bee27f000 (f6922e27c000-f6922e27f000)
shared_lib (libc-2.31.so): 7f8bee27f000-7f8bee282000 (f6922e27f000-f6922e282000)
seg_TBD: 7f8bee282000-7f8bee286000 (f6922e282000-f6922e286000)
shared_lib (libpthread-2.31.so): 7f8bee286000-7f8bee28d000 (f6922e286000-f6922e28d000)
shared_lib (libpthread-2.31.so): 7f8bee28d000-7f8bee29e000 (f6922e28d000-f6922e29e000)
shared_lib (libpthread-2.31.so): 7f8bee29e000-7f8bee2a3000 (f6922e29e000-f6922e2a3000)
shared_lib (libpthread-2.31.so): 7f8bee2a3000-7f8bee2a4000 (f6922e2a3000-f6922e2a4000)
shared_lib (libpthread-2.31.so): 7f8bee2a4000-7f8bee2a5000 (f6922e2a4000-f6922e2a5000)
seg_TBD: 7f8bee2a5000-7f8bee2ab000 (f6922e2a5000-f6922e2ab000)
shared_lib (ld-2.31.so): 7f8bee2ba000-7f8bee2bb000 (f6922e2ba000-f6922e2bb000)
shared_lib (ld-2.31.so): 7f8bee2bb000-7f8bee2de000 (f6922e2bb000-f6922e2de000)
shared_lib (ld-2.31.so): 7f8bee2de000-7f8bee2e6000 (f6922e2de000-f6922e2e6000)
shared_lib (ld-2.31.so): 7f8bee2e7000-7f8bee2e8000 (f6922e2e7000-f6922e2e8000)
shared_lib (ld-2.31.so): 7f8bee2e8000-7f8bee2e9000 (f6922e2e8000-f6922e2e9000)
seg_TBD: 7f8bee2e9000-7f8bee2ea000 (f6922e2e9000-f6922e2ea000)
seg_TBD: 7ffe14e4e000-7ffe14e6f000 (f70454e4e000-f70454e6f000)
seg_TBD: 7ffe14ec0000-7ffe14ec4000 (f70454ec0000-f70454ec4000)
seg_TBD: 7ffe14ec4000-7ffe14ec6000 (f70454ec4000-f70454ec6000)
shared_var: 4040a0 (7706404040a0)
TLS_addr: 7f8bed08e6fc (f6922d08e6fc)
local_var_addr: 7f8bed085274 (f6922d085274)
```

#### 結論 1

1. 可以發現 code segment、data segment、heap segment、stack segment，可以推測出 bss segment 也是相同的virtual和physical address（arg segment 跟 env segment 應該也是共用的，只是沒印出來）

2. 可以發現編譯過後的 executable file `get_address_test.o` 是共用的

3. 可以發現各種 library，`libc-2.31.so`、`libpthread-2.31.so`、`ld-2.31.so` 在 thread 之間也是相同的virtual和physical address

4. 可以發現全域變數 `shared_var` 是相同的virtual和physical address，因為存在 data segment 裡頭

5. 可以發現加上 `__thread` 前綴的變數因為存在各個thread的instance的 TLS segment，所以推測可以用pointer去取得TLS，但是他的lifetime是隨著thread的lifetime的，可是目前找不到一個方法去access到他的address，所以應該是不可讀也不可寫的

6. 可以發現每個 thread 的 local variable 沒有相同的virtual和physical address

## Question 2

### User Space Test Code 2

```c=
#include <syscall.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/wait.h>
#include <stdlib.h>

int shared_var = 0;

#define __NR_get_address 449
#define MAX_BUF_SIZE 128

enum MODE
{
    BY_SEGMENT = 0,
    BY_VIRTUAL_ADDRESS = 1,
};

struct Segment
{
    unsigned long int start_addr;
    unsigned long int end_addr;
    char seg_name[MAX_BUF_SIZE];
    char lib_name[MAX_BUF_SIZE];
};

struct ProcessSegments
{
    pid_t pid;
    struct Segment code_seg;
    struct Segment data_seg;
    struct Segment heap_seg;
    struct Segment stack_seg;
    struct Segment mmap_segs[MAX_BUF_SIZE];
    int mmap_seg_count;
};

struct AddrInfo
{
    unsigned long int virt_addr;
    unsigned long int phys_addr;
};

unsigned long int get_phys_addr(unsigned long int virt_addr)
{
    struct AddrInfo addr_info;
    addr_info.virt_addr = virt_addr;

    syscall(__NR_get_address, BY_VIRTUAL_ADDRESS, (void *)&addr_info);

    return addr_info.phys_addr;
}

int main()
{
    int pid = fork();

    if (pid == 0)
    {
        struct ProcessSegments process_segs;
        process_segs.pid = getpid();

        printf("\n--- CHILD PROCESS START ---\n");

        // call get_address syscall
        syscall(__NR_get_address, BY_SEGMENT, (void *)&process_segs);
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.code_seg.seg_name, process_segs.code_seg.start_addr, process_segs.code_seg.end_addr, get_phys_addr(process_segs.code_seg.start_addr), get_phys_addr(process_segs.code_seg.end_addr));
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.data_seg.seg_name, process_segs.data_seg.start_addr, process_segs.data_seg.end_addr, get_phys_addr(process_segs.data_seg.start_addr), get_phys_addr(process_segs.data_seg.end_addr));
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.heap_seg.seg_name, process_segs.heap_seg.start_addr, process_segs.heap_seg.end_addr, get_phys_addr(process_segs.heap_seg.start_addr), get_phys_addr(process_segs.heap_seg.end_addr));
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.stack_seg.seg_name, process_segs.stack_seg.start_addr, process_segs.stack_seg.end_addr, get_phys_addr(process_segs.stack_seg.start_addr), get_phys_addr(process_segs.stack_seg.end_addr));

        for (int i = 0; i < process_segs.mmap_seg_count; i++)
        {
            if (strcmp(process_segs.mmap_segs[i].lib_name, "NULL") != 0)
            {
                printf("%s (%s): %lx-%lx (%lx-%lx)\n", process_segs.mmap_segs[i].seg_name, process_segs.mmap_segs[i].lib_name, process_segs.mmap_segs[i].start_addr, process_segs.mmap_segs[i].end_addr, get_phys_addr(process_segs.mmap_segs[i].start_addr), get_phys_addr(process_segs.mmap_segs[i].end_addr));
            }
            else
            {
                printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.mmap_segs[i].seg_name, process_segs.mmap_segs[i].start_addr, process_segs.mmap_segs[i].end_addr, get_phys_addr(process_segs.mmap_segs[i].start_addr), get_phys_addr(process_segs.mmap_segs[i].end_addr));
            }
        }

        // print the shared var address
        printf("shared_var: %lx (%lx)\n", (unsigned long int)&shared_var, get_phys_addr((unsigned long int)&shared_var));

        exit(0);
    }
    else if (pid > 0)
    {
        int _ = wait(NULL);

        struct ProcessSegments process_segs;
        process_segs.pid = getpid();

        printf("\n--- PARENT PROCESS START ---\n");

        // call get_address syscall
        syscall(__NR_get_address, BY_SEGMENT, (void *)&process_segs);
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.code_seg.seg_name, process_segs.code_seg.start_addr, process_segs.code_seg.end_addr, get_phys_addr(process_segs.code_seg.start_addr), get_phys_addr(process_segs.code_seg.end_addr));
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.data_seg.seg_name, process_segs.data_seg.start_addr, process_segs.data_seg.end_addr, get_phys_addr(process_segs.data_seg.start_addr), get_phys_addr(process_segs.data_seg.end_addr));
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.heap_seg.seg_name, process_segs.heap_seg.start_addr, process_segs.heap_seg.end_addr, get_phys_addr(process_segs.heap_seg.start_addr), get_phys_addr(process_segs.heap_seg.end_addr));
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.stack_seg.seg_name, process_segs.stack_seg.start_addr, process_segs.stack_seg.end_addr, get_phys_addr(process_segs.stack_seg.start_addr), get_phys_addr(process_segs.stack_seg.end_addr));

        for (int i = 0; i < process_segs.mmap_seg_count; i++)
        {
            if (strcmp(process_segs.mmap_segs[i].lib_name, "NULL") != 0)
            {
                printf("%s (%s): %lx-%lx (%lx-%lx)\n", process_segs.mmap_segs[i].seg_name, process_segs.mmap_segs[i].lib_name, process_segs.mmap_segs[i].start_addr, process_segs.mmap_segs[i].end_addr, get_phys_addr(process_segs.mmap_segs[i].start_addr), get_phys_addr(process_segs.mmap_segs[i].end_addr));
            }
            else
            {
                printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.mmap_segs[i].seg_name, process_segs.mmap_segs[i].start_addr, process_segs.mmap_segs[i].end_addr, get_phys_addr(process_segs.mmap_segs[i].start_addr), get_phys_addr(process_segs.mmap_segs[i].end_addr));
            }
        }

        // print the shared var address
        printf("shared_var: %lx (%lx)\n", (unsigned long int)&shared_var, get_phys_addr((unsigned long int)&shared_var));
    }

    return 0;
}
```

### Test Command 2

```c=
gcc -o get_adress_between_two_proc get_adress_between_two_proc.c
```

### 實驗成果 2

#### PROCESS 1

```bash=

#include <syscall.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

int shared_var = 0;

#define __NR_get_address 449
#define MAX_BUF_SIZE 128

enum MODE
{
    BY_SEGMENT = 0,
    BY_VIRTUAL_ADDRESS = 1,
};

struct Segment
{
    unsigned long int start_addr;
    unsigned long int end_addr;
    char seg_name[MAX_BUF_SIZE];
    char lib_name[MAX_BUF_SIZE];
};

struct ProcessSegments
{
    pid_t pid;
    struct Segment code_seg;
    struct Segment data_seg;
    struct Segment heap_seg;
    struct Segment stack_seg;
    struct Segment mmap_segs[MAX_BUF_SIZE];
    int mmap_seg_count;
};

struct AddrInfo
{
    unsigned long int virt_addr;
    unsigned long int phys_addr;
};

unsigned long int get_phys_addr(unsigned long int virt_addr)
{
    struct AddrInfo addr_info;
    addr_info.virt_addr = virt_addr;

    syscall(__NR_get_address, BY_VIRTUAL_ADDRESS, (void *)&addr_info);

    return addr_info.phys_addr;
}

int main()
{
    int pid = fork();

    if (pid == 0)
    {
        struct ProcessSegments process_segs;
        process_segs.pid = getpid();

        printf("\n--- CHILD PROCESS START ---\n");

        // call get_address syscall
        syscall(__NR_get_address, BY_SEGMENT, (void *)&process_segs);
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.code_seg.seg_name, process_segs.code_seg.start_addr, process_segs.code_seg.end_addr, get_phys_addr(process_segs.code_seg.start_addr), get_phys_addr(process_segs.code_seg.end_addr));
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.data_seg.seg_name, process_segs.data_seg.start_addr, process_segs.data_seg.end_addr, get_phys_addr(process_segs.data_seg.start_addr), get_phys_addr(process_segs.data_seg.end_addr));
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.heap_seg.seg_name, process_segs.heap_seg.start_addr, process_segs.heap_seg.end_addr, get_phys_addr(process_segs.heap_seg.start_addr), get_phys_addr(process_segs.heap_seg.end_addr));
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.stack_seg.seg_name, process_segs.stack_seg.start_addr, process_segs.stack_seg.end_addr, get_phys_addr(process_segs.stack_seg.start_addr), get_phys_addr(process_segs.stack_seg.end_addr));

        for (int i = 0; i < process_segs.mmap_seg_count; i++)
        {
            if (strcmp(process_segs.mmap_segs[i].lib_name, "NULL") != 0)
            {
                printf("%s (%s): %lx-%lx (%lx-%lx)\n", process_segs.mmap_segs[i].seg_name, process_segs.mmap_segs[i].lib_name, process_segs.mmap_segs[i].start_addr, process_segs.mmap_segs[i].end_addr, get_phys_addr(process_segs.mmap_segs[i].start_addr), get_phys_addr(process_segs.mmap_segs[i].end_addr));
            }
            else
            {
                printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.mmap_segs[i].seg_name, process_segs.mmap_segs[i].start_addr, process_segs.mmap_segs[i].end_addr, get_phys_addr(process_segs.mmap_segs[i].start_addr), get_phys_addr(process_segs.mmap_segs[i].end_addr));
            }
        }

        // print the shared var address
        printf("shared_var: %lx (%lx)\n", (unsigned long int)&shared_var, get_phys_addr((unsigned long int)&shared_var));

        exit(0);
    }
    else if (pid > 0)
    {
        int _ = wait(NULL);

        struct ProcessSegments process_segs;
        process_segs.pid = getpid();

        printf("\n--- PARENT PROCESS START ---\n");

// call get_address syscall
        syscall(__NR_get_address, BY_SEGMENT, (void *)&process_segs);
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.code_seg.seg_name, process_segs.code_seg.start_addr, process_segs.code_seg.end_addr, get_phys_addr(process_segs.code_seg.start_addr), get_phys_addr(process_segs.code_seg.end_addr));
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.data_seg.seg_name, process_segs.data_seg.start_addr, process_segs.data_seg.end_addr, get_phys_addr(process_segs.data_seg.start_addr), get_phys_addr(process_segs.data_seg.end_addr));
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.heap_seg.seg_name, process_segs.heap_seg.start_addr, process_segs.heap_seg.end_addr, get_phys_addr(process_segs.heap_seg.start_addr), get_phys_addr(process_segs.heap_seg.end_addr));
        printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.stack_seg.seg_name, process_segs.stack_seg.start_addr, process_segs.stack_seg.end_addr, get_phys_addr(process_segs.stack_seg.start_addr), get_phys_addr(process_segs.stack_seg.end_addr));

        for (int i = 0; i < process_segs.mmap_seg_count; i++)
        {
            if (strcmp(process_segs.mmap_segs[i].lib_name, "NULL") != 0)
            {
                printf("%s (%s): %lx-%lx (%lx-%lx)\n", process_segs.mmap_segs[i].seg_name, process_segs.mmap_segs[i].lib_name, process_segs.mmap_segs[i].start_addr, process_segs.mmap_segs[i].end_addr, get_phys_addr(process_segs.mmap_segs[i].start_addr), get_phys_addr(process_segs.mmap_segs[i].end_addr));
            }
            else
            {
                printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.mmap_segs[i].seg_name, process_segs.mmap_segs[i].start_addr, process_segs.mmap_segs[i].end_addr, get_phys_addr(process_segs.mmap_segs[i].start_addr), get_phys_addr(process_segs.mmap_segs[i].end_addr));
            }
        }

        // print the shared var address
        printf("shared_var: %lx (%lx)\n", (unsigned long int)&shared_var, get_phys_addr((unsigned long int)&shared_var));
    }

    return 0;
}

--- CHILD PROCESS START ---
code_seg: 401000-401c85 (63e940401000-63e940401c85)
data_seg: 403e10-404070 (63e940403e10-63e940404070)
heap_seg: 1698000-16b9000 (63e941698000-63e9416b9000)
stack_seg: 7fff05388f50-7fff05388f71 (e3e845388f50-e3e845388f71)
shared_lib (get_address_between_procs.o): 400000-401000 (63e940400000-63e940401000)
shared_lib (get_address_between_procs.o): 401000-402000 (63e940401000-63e940402000)
shared_lib (get_address_between_procs.o): 402000-403000 (63e940402000-63e940403000)
shared_lib (get_address_between_procs.o): 403000-404000 (63e940403000-63e940404000)
shared_lib (get_address_between_procs.o): 404000-405000 (63e940404000-63e940405000)
seg_TBD: 1698000-16b9000 (63e941698000-63e9416b9000)
shared_lib (libc-2.31.so): 7ff2557c4000-7ff2557e9000 (e3db957c4000-e3db957e9000)
shared_lib (libc-2.31.so): 7ff2557e9000-7ff255961000 (e3db957e9000-e3db95961000)
shared_lib (libc-2.31.so): 7ff255961000-7ff2559ab000 (e3db95961000-e3db959ab000)
shared_lib (libc-2.31.so): 7ff2559ab000-7ff2559ac000 (e3db959ab000-e3db959ac000)
shared_lib (libc-2.31.so): 7ff2559ac000-7ff2559af000 (e3db959ac000-e3db959af000)
shared_lib (libc-2.31.so): 7ff2559af000-7ff2559b2000 (e3db959af000-e3db959b2000)
seg_TBD: 7ff2559b2000-7ff2559b8000 (e3db959b2000-e3db959b8000)
shared_lib (ld-2.31.so): 7ff2559c7000-7ff2559c8000 (e3db959c7000-e3db959c8000)
shared_lib (ld-2.31.so): 7ff2559c8000-7ff2559eb000 (e3db959c8000-e3db959eb000)
shared_lib (ld-2.31.so): 7ff2559eb000-7ff2559f3000 (e3db959eb000-e3db959f3000)
shared_lib (ld-2.31.so): 7ff2559f4000-7ff2559f5000 (e3db959f4000-e3db959f5000)
shared_lib (ld-2.31.so): 7ff2559f5000-7ff2559f6000 (e3db959f5000-e3db959f6000)
seg_TBD: 7ff2559f6000-7ff2559f7000 (e3db959f6000-e3db959f7000)
seg_TBD: 7fff0536a000-7fff0538b000 (e3e84536a000-e3e84538b000)
seg_TBD: 7fff053f0000-7fff053f4000 (e3e8453f0000-e3e8453f4000)
seg_TBD: 7fff053f4000-7fff053f6000 (e3e8453f4000-e3e8453f6000)
shared_var: 404074 (63e940404074)

--- PARENT PROCESS START ---
code_seg: 401000-401c85 (63e940401000-63e940401c85)
data_seg: 403e10-404070 (63e940403e10-63e940404070)
heap_seg: 1698000-16b9000 (63e941698000-63e9416b9000)
stack_seg: 7fff05388f50-7fff05388f71 (e3e845388f50-e3e845388f71)
shared_lib (get_address_between_procs.o): 400000-401000 (63e940400000-63e940401000)
shared_lib (get_address_between_procs.o): 401000-402000 (63e940401000-63e940402000)
shared_lib (get_address_between_procs.o): 402000-403000 (63e940402000-63e940403000)
shared_lib (get_address_between_procs.o): 403000-404000 (63e940403000-63e940404000)
shared_lib (get_address_between_procs.o): 404000-405000 (63e940404000-63e940405000)
seg_TBD: 1698000-16b9000 (63e941698000-63e9416b9000)
shared_lib (libc-2.31.so): 7ff2557c4000-7ff2557e9000 (e3db957c4000-e3db957e9000)
shared_lib (libc-2.31.so): 7ff2557e9000-7ff255961000 (e3db957e9000-e3db95961000)
shared_lib (libc-2.31.so): 7ff255961000-7ff2559ab000 (e3db95961000-e3db959ab000)
shared_lib (libc-2.31.so): 7ff2559ab000-7ff2559ac000 (e3db959ab000-e3db959ac000)
shared_lib (libc-2.31.so): 7ff2559ac000-7ff2559af000 (e3db959ac000-e3db959af000)
shared_lib (libc-2.31.so): 7ff2559af000-7ff2559b2000 (e3db959af000-e3db959b2000)
seg_TBD: 7ff2559b2000-7ff2559b8000 (e3db959b2000-e3db959b8000)
shared_lib (ld-2.31.so): 7ff2559c7000-7ff2559c8000 (e3db959c7000-e3db959c8000)
shared_lib (ld-2.31.so): 7ff2559c8000-7ff2559eb000 (e3db959c8000-e3db959eb000)
shared_lib (ld-2.31.so): 7ff2559eb000-7ff2559f3000 (e3db959eb000-e3db959f3000)
shared_lib (ld-2.31.so): 7ff2559f4000-7ff2559f5000 (e3db959f4000-e3db959f5000)
shared_lib (ld-2.31.so): 7ff2559f5000-7ff2559f6000 (e3db959f5000-e3db959f6000)
seg_TBD: 7ff2559f6000-7ff2559f7000 (e3db959f6000-e3db959f7000)
seg_TBD: 7fff0536a000-7fff0538b000 (e3e84536a000-e3e84538b000)
seg_TBD: 7fff053f0000-7fff053f4000 (e3e8453f0000-e3e8453f4000)
seg_TBD: 7fff053f4000-7fff053f6000 (e3e8453f4000-e3e8453f6000)
shared_var: 404074 (63e940404074)
```

#### 結論 2

1. 可以發現 code segment、data segment ,heap segment,stack segment 的virtual和physical address是一樣的（推測 bss segment 應該也是一樣）

2. 可以發現編譯過後的 executable file `get_address_between_procs.o` virtual和physical address是一樣的

3. 可以發現各種 library，`libc-2.31.so`、`libpthread-2.31.so`、`ld-2.31.so` 在 process 之間virtual和physical address是一樣的

4. 可以發現全域變數 `shared_var` virtual和physical address是一樣的,因為存在data段裡

## 後記 - 關於kernel module的那一回事

- 因為重編kernel要很久，所以我們用了kernel module

- 我們當初是這樣用的 當然不是下面看到臭臭長長的樣子
- 檔名叫hello.c

```c=
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/kthread.h>

#define PAGE_SHIFT 12
#define page_to_phys(page) ((dma_addr_t)page_to_pfn(page) << PAGE_SHIFT)

#define UL(x) (_UL(x))
#define _UL(x) (_AC(x, UL))
#define __START_KERNEL_map _AC(0xffffffff80000000, UL)
#define PAGE_OFFSET_BASE_L4 _AC(0xffff888000000000, UL)

struct task_struct *task1;
struct task_struct *task2;

unsigned long virt_to_phys(unsigned long x)
{
  unsigned long y = x - __START_KERNEL_map;

  /* use the carry flag to determine if x was < __START_KERNEL_map */
  x = y + ((x > y) ? phys_base : (__START_KERNEL_map - PAGE_OFFSET));

  return x;
}
MODULE_LICENSE("GPL");


unsigned long get_physical_address_by_shift(unsigned long virtual_address)
{
    unsigned long physical_address;
    struct page* page;
    
    page= virt_to_page(virtual_address);
    physical_address = page_to_phys(page);
    
    return physical_address;
}

unsigned long get_physical_address_by_hand(unsigned long virtual_address)
{
    unsigned long physical_address;

    
    physical_address = virt_to_phys(virtual_address);
    
    
    return physical_address;
}

void get_detailed_segment_address(pid_t current_pid)
{
    unsigned long base_address;
    struct task_struct* task;
    struct vm_area_struct* current_vm_area;
    
for_each_process(task)
    {
        if(task->pid == current_pid)
        {
           break;
        }
    }   
    if (!task)
    {
        return;
    }

    current_vm_area = task->mm->mmap;
 if(current_vm_area) {
        base_address = current_vm_area->vm_start;
    }
    printk("code_start: %lx\n", task->mm->start_code);
    printk("code_end: %lx\n", task->mm->end_code);
    printk("data_start: %lx\n", task->mm->start_data);
    printk("data_end: %lx\n", task->mm->end_data);
    printk("heap_start: %lx\n", task->mm->start_brk);
    printk("heap_end: %lx\n", task->mm->brk);
    printk("stack_start: %lx\n", task->mm->start_stack);
    printk("stack_end: %lx\n", task->mm->start_stack + task->mm->stack_vm);
    for (current_vm_area = task->mm->mmap; current_vm_area; current_vm_area = current_vm_area->vm_next)
    {
        printk("seg: %lx-%lx\n", current_vm_area->vm_start, current_vm_area->vm_end);
        printk("seg_by_hand: %lx-%lx\n",get_physical_address_by_hand(current_vm_area->vm_start),get_physical_address_by_hand(current_vm_area->vm_end));
        printk("seg_by_shift: %lx-%lx\n",get_physical_address_by_shift(current_vm_area->vm_start),get_physical_address_by_shift(current_vm_area->vm_end));
        if (current_vm_area->vm_file)
        {
            printk("seg_name: %s\n", current_vm_area->vm_file->f_path.dentry->d_name.name);
        }
    }
 return;
}

static void *child(void *data){
int *n;
n = (int *)data;
int i = 0;
while(i < 10){
printk("%d\n",*n);
i++;
}
kthread_exit(NULL);
}

static int  __init hello_init(void){
int x = 1, y =2;
int *p1, *p2;
p1 = &x;
p2 = &y;
task1 = kthread_run(&child,(void*)&p1,"thread 1");
task2  = kthread_run(&child,(void*)&p2,"thread 2");

printk(KERN_INFO "Process Started\n");

pthread_join(t,NULL);
pthread_join(t1,NULL);


get_detailed_segment_address(current->pid);

return 0;
}


static void __exit hello_exit(void){

printk(KERN_INFO "Process ended\n");
kthread_stop(task1);
kthread_stop(task2);
}

module_init(hello_init);
module_exit(hello_exit);
```

- license要記得填 不然compile會出錯

- 然後寫Makefile

```markdown
obj-m += hello-1.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

- 下make指令

```shell
make
```

- 可以用modinfo查看make出來的.ko檔

```shell
modinfo hello.ko
```

- insmod載入ko檔

```shell
sudo insmod hello.ko
```

- 不會發生任何事
- lsmod查看

```shell
lsmod | grep hello
```

- dmesg一下

```shell
dmesg
```

- 會看到最後有輸出HELLO WORLD

- 移除掉的話用rmmod

```shell=
sudo rmmod hello
```

- dmesg可以看到
