#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
pthread_barrier_t barrier;
typedef struct {
    int id;
    char policy[10];
    int priority;
    float exec_time;
} thread_info_t;
void *worker_thread(void *arg) {
    thread_info_t *info = (thread_info_t *)arg;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);               // 清除所有 CPU
    CPU_SET(0, &cpuset);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == -1) {
        perror("sched_setaffinity");
        return NULL;
    }             // 設置 CPU 0（假設所有執行緒都運行在 CPU 0）
    pthread_barrier_wait(&barrier);
    // 模擬忙等待 (Busy Waiting)
    for (int i=0; i< 3; i++){
        printf("Thread %d is starting\n", info->id);
        volatile double result = 0.0; // 使用 volatile 防止編譯器優化
        double end_time = info->exec_time;
        double elapsed_time = 0.0;
        struct timespec start, current;
        
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);

        while (elapsed_time < end_time) {
            // 執行一些簡單計算以模擬busy waiting
            for (int i = 0; i < 1000; i++) {
                result += i * 0.0001;
            }

            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &current);
            elapsed_time = (current.tv_sec - start.tv_sec) + 
                        (current.tv_nsec - start.tv_nsec) / 1e9;
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int num_threads = 0;
    float exec_time = 0;
    char *schedules = NULL;
    char *priorities = NULL;
    int opt;
    // 解析命令列參數
    while ((opt = getopt(argc, argv, "n:t:s:p:")) != -1) {
        switch (opt) {
            case 'n':
                num_threads = atoi(optarg);
                break;
            case 't':
                exec_time = atof(optarg);
                break;
            case 's':
                schedules = strdup(optarg);
                break;
            case 'p':
                priorities = strdup(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s -n <num_threads> -t <time> -s <policies> -p <priorities>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (num_threads <= 0 || exec_time <= 0 || !schedules || !priorities) {
        fprintf(stderr, "Invalid arguments\n");
        exit(EXIT_FAILURE);
    }

    pthread_t threads[num_threads];
    pthread_attr_t attr;
    thread_info_t thread_info[num_threads];
    char *sched_tokens[num_threads];
    char *prio_tokens[num_threads];
    int i;

    // 分割排程策略和優先級
    char *token = strtok(schedules, ",");
    for (i = 0; i < num_threads && token != NULL; i++) {
        sched_tokens[i] = token;
        token = strtok(NULL, ",");
    }
    if (i != num_threads) {
        fprintf(stderr, "Mismatch in number of scheduling policies\n");
        exit(EXIT_FAILURE);
    }

    token = strtok(priorities, ",");
    for (i = 0; i < num_threads && token != NULL; i++) {
        prio_tokens[i] = token;
        token = strtok(NULL, ",");
    }
    if (i != num_threads) {
        fprintf(stderr, "Mismatch in number of priorities\n");
        exit(EXIT_FAILURE);
    }

    // 初始化執行緒屬性
    pthread_attr_init(&attr);
    pthread_barrier_init(&barrier, NULL, num_threads);

    for (i = 0; i < num_threads; i++) {
        thread_info[i].id = i;
        strcpy(thread_info[i].policy, sched_tokens[i]);
        thread_info[i].priority = atoi(prio_tokens[i]);
        thread_info[i].exec_time = exec_time;

        struct sched_param param;

        if (strcmp(thread_info[i].policy, "FIFO") == 0) {
            pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
        } else if (strcmp(thread_info[i].policy, "RR") == 0) {
            pthread_attr_setschedpolicy(&attr, SCHED_RR);
        } else {
            pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
        }

        if (thread_info[i].priority != -1) {
            param.sched_priority = thread_info[i].priority;
            pthread_attr_setschedparam(&attr, &param);
            pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
        } else {
            pthread_attr_setinheritsched(&attr, PTHREAD_INHERIT_SCHED);
        }

        // 建立執行緒
        if (pthread_create(&threads[i], &attr, worker_thread, &thread_info[i]) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    // 等待所有執行緒完成
    for (i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    // 清理
    pthread_attr_destroy(&attr);
    pthread_barrier_destroy(&barrier);
    free(schedules);
    free(priorities);

    //printf("All threads finished\n");
    return 0;
}