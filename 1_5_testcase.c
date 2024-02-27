#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>
#include <time.h>

#define FILENAME "test.txt"
#define PAGE_SIZE 4096

int stop_signal = 0;

void signal_handler(int signo) {
    if (signo == SIGINT) {
        stop_signal = 1;
    }
}

unsigned long print_anon_mem_usage() {
    char path[256];
    sprintf(path, "/proc/%d/smaps", getpid());

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        perror("Error opening smaps file");
        return 0;
    }

    unsigned long anon_memory = 0;
    char line[256];
    while (fgets(line, sizeof(line), file) != NULL) {
        unsigned long size;
        if (sscanf(line, "Anonymous: %lu", &size) == 1) {
            anon_memory += size;
        }
    }

    fclose(file);
    printf("pid: %d anonymous memory usage: %lu KB\n", getpid(), anon_memory);
}


void create_file_and_touch_memory(int minutes, int hours) {
    unsigned long size = (hours * 1000) * PAGE_SIZE + minutes;
    unsigned long size2 = (1024 * 1024);

    // Create anonymous memory pages
    //char* anonymous_memory = (char*)mmap(NULL, (size_t)hours * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char* anonymous_memory = (char*)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (anonymous_memory == MAP_FAILED) {
        perror("Error mapping anonymous memory");
        exit(EXIT_FAILURE);
    }

    // Touch all pages in anonymous memory
    for (size_t i = 0; i < size; i += PAGE_SIZE) {
        anonymous_memory[i] = 0; // Touch the page by writing to it
    }

    printf("The tracing script should output following value when run parallelly:\n");

    // Periodically print memory usage until Ctrl+C is pressed
    printf("size %lu\n", size);
    while (!stop_signal) {
        print_anon_mem_usage();
        sleep(5);
        char *anonymous_memory2 = (char*)mmap(NULL, size2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (anonymous_memory2 == MAP_FAILED) {
            perror("Error mapping anonymous memory");
            exit(EXIT_FAILURE);
        }
        for (size_t i = 0; i < size2; i += PAGE_SIZE) {
            anonymous_memory2[i] = 0; // Touch the page by writing to it
        }
    }

    // Cleanup
    munmap(anonymous_memory, (size_t)hours * PAGE_SIZE);
}

int main() {
    signal(SIGINT, signal_handler);

    // Get current time
    time_t current_time;
    struct tm *time_info;

    time(&current_time);
    time_info = localtime(&current_time);

    int minutes = time_info->tm_min;
    int hours = time_info->tm_hour;

    create_file_and_touch_memory(minutes, hours);

    return 0;
}