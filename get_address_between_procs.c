#include <syscall.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

int shared_var = 0;

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


int main() {
    struct ProcessSegments process_segs;    

    printf("\n--- PROCESS START ---\n");
    
    process_segs.pid = getpid();
    
    // call get_address syscall
    syscall(__NR_get_address, BY_SEGMENT, (void *) &process_segs);
    printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.code_seg.seg_name, process_segs.code_seg.start_addr, process_segs.code_seg.end_addr, get_phys_addr(process_segs.code_seg.start_addr), get_phys_addr(process_segs.code_seg.end_addr));
    printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.data_seg.seg_name, process_segs.data_seg.start_addr, process_segs.data_seg.end_addr, get_phys_addr(process_segs.data_seg.start_addr), get_phys_addr(process_segs.data_seg.end_addr));
    printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.heap_seg.seg_name, process_segs.heap_seg.start_addr, process_segs.heap_seg.end_addr, get_phys_addr(process_segs.heap_seg.start_addr), get_phys_addr(process_segs.heap_seg.end_addr));
    printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.stack_seg.seg_name, process_segs.stack_seg.start_addr, process_segs.stack_seg.end_addr, get_phys_addr(process_segs.stack_seg.start_addr), get_phys_addr(process_segs.stack_seg.end_addr));
    
    for (int i = 0; i < process_segs.mmap_seg_count; i++) {
        if (strcmp(process_segs.mmap_segs[i].lib_name, "NULL") != 0) {
            printf("%s (%s): %lx-%lx (%lx-%lx)\n", process_segs.mmap_segs[i].seg_name, process_segs.mmap_segs[i].lib_name, process_segs.mmap_segs[i].start_addr, process_segs.mmap_segs[i].end_addr, get_phys_addr(process_segs.mmap_segs[i].start_addr), get_phys_addr(process_segs.mmap_segs[i].end_addr));
        } else {            
            printf("%s: %lx-%lx (%lx-%lx)\n", process_segs.mmap_segs[i].seg_name, process_segs.mmap_segs[i].start_addr, process_segs.mmap_segs[i].end_addr, get_phys_addr(process_segs.mmap_segs[i].start_addr), get_phys_addr(process_segs.mmap_segs[i].end_addr));
        }
    }

    // print the shared var address
    printf("shared_var: %lx (%lx)\n", (unsigned long int) &shared_var, get_phys_addr((unsigned long int) &shared_var));

    sleep(3000);

    return 0;
}