#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <asm/errno.h>
#include <asm/io.h>

#define MAX_BUF_SIZE 32

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