#include "iostream"
#include "pthread.h"
#include <unistd.h>

void* t_run(void *){
    char *args[] = {"ls", NULL};
    if (execve("/bin/ls", args, NULL) == -1) {
    }
    return nullptr;
}

void * run(void *){
    char *args[] = {"ls", NULL};
    if (execve("/bin/ls", args, NULL) == -1) {
    }
    printf("I am Thread");
    return nullptr;
}

int main(){
    pthread_t thread1, thread2, thread3, thread4, thread5, thread6;
    pthread_create(&thread1, NULL, &run, NULL);
    pthread_create(&thread2, NULL, &run, NULL);
    pthread_create(&thread3, NULL, &run, NULL);
    pthread_create(&thread4, NULL, &run, NULL);
    pthread_create(&thread5, NULL, &run, NULL);
    pthread_create(&thread6, NULL, &run, NULL);
    return 0;
}