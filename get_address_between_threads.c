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