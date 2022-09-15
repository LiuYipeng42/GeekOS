/*
 * Synchronization primitives
 * Copyright (c) 2001,2004 David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.13 $
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/int.h>
#include <geekos/kassert.h>
#include <geekos/kthread.h>
#include <geekos/screen.h>
#include <geekos/synch.h>

#include <geekos/errno.h>
#include <geekos/malloc.h>
#include <geekos/string.h>
/* 信号量列表 */
struct Semaphore_List g_semList;
/* 当前信号量 ID 最大值 */
int g_curSID = 0;

/* 信号量入列表 */
static __inline__ void Enqueue_Semaphore(struct Semaphore_List* list,
                                         struct Semaphore* sem) {
    Add_To_Back_Of_Semaphore_List(list, sem);
}
/* 信号量出列表 */
static __inline__ void Remove_Semaphore(struct Semaphore_List* list,
                                        struct Semaphore* sem) {
    Remove_From_Semaphore_List(list, sem);
}

/* 根据信号量名检查信号量是否存在 */
pSemaphore isSemExistByName(char* nameSem, int nameLen) {
    if (g_curSID == 0)
        return NULL;

    pSemaphore sem = g_semList.head;
    while (sem != NULL) {
        if (strncmp(sem->semaphoreName, nameSem, nameLen) == 0)
            break;
        sem = Get_Next_In_Semaphore_List(sem);
    }
    return sem;
}

/* 根据信号量名检查信号量是否存在 */
pSemaphore isSemExistBySID(int sid) {
    pSemaphore sem = g_semList.head;
    while (sem != NULL) {
        if (sem->semaphoreID == sid)
            break;
        sem = Get_Next_In_Semaphore_List(sem);
    }
    return sem;
}

int getIndexInRegThreadList(pSemaphore sem) {
    int i;
    for (i = 0; i < sem->registeredThreadCount; i++)
        if (sem->registeredThreads[i] == g_currentThread)
            break;
    return (i != sem->registeredThreadCount ? i : -1);
}

/* 创建一个信号量 */
int Create_Semaphore(char* semName, int nameLen, int initCount) {
    // project3 Create_Semaphore
    /* 错误中断 */
    KASSERT(semName != NULL);
    KASSERT(nameLen > 0 && nameLen <= MAX_SEMAPHORE_NAME);
    KASSERT(initCount >= 0);
    KASSERT(strnlen(semName, MAX_SEMAPHORE_NAME) == nameLen);

    /* 如果未初始化信号量列表结构体则先进行初始化 */
    if (g_curSID == 0) {
        g_semList.head = NULL;
        g_semList.tail = NULL;
    }
    /* 查找是否已经存在同名信号量 */
    pSemaphore sem = isSemExistByName(semName, nameLen);
    /* 如果不存在则新建一个信号量 */
    if (sem == NULL) {
        /* 初始化信号量 */
        sem = (pSemaphore)Malloc(sizeof(struct Semaphore));
        if (sem == NULL) {
            Print("Error! Out of Memory Space\n");
            return ENOMEM;
        }
        memset(sem, 0, sizeof(struct Semaphore));

        /* 设置信号量相关值  */
		// 设置信号量 ID
        g_curSID++;
        sem->semaphoreID = g_curSID;
		// 设置信号量名称
        strncpy(sem->semaphoreName, semName, MAX_SEMAPHORE_NAME);
		// 设置信号量初始值
        sem->value = initCount;
		// 注册该信号量的线程数量
        sem->registeredThreadCount = 0;
		// 清空等待该信号的线程队列
        Clear_Thread_Queue(&sem->waitingThreads);

        /* 将新创建的信号量加入到信号量列表中 */
        Add_To_Back_Of_Semaphore_List(&g_semList, sem);
    }

	// 某个进程创建信号量就代表此线程注册了一个信号量，
    // 所以要把当前线程放入对应信号量的 registeredThreads 中
    sem->registeredThreads[sem->registeredThreadCount] = g_currentThread;
    sem->registeredThreadCount++;

    return sem->semaphoreID;
}

/* 信号量 P(获取)操作 */
int P(int sid) {
    // project3 P
    /* 错误中断 */
    KASSERT(sid > 0);

	// 检查信号量 ID 是否存在，如果存在则返回此信号量的地址
    pSemaphore sem = isSemExistBySID(sid);
    if (sem == NULL) {
        Print("Error! Connot Find Semaphore with SID=%d\n", sid);
        return -1;
    }

	// 获得当前线程在此信号量的注册列表中的索引，用于检测当前进程是否真的使用了此信号量
    int threadIndex = getIndexInRegThreadList(sem);
    if (threadIndex == -1) {
        Print("Error! Current Thread is not Using the Semaphore with SID=%d\n",
              sid);
        return -1;
    }

	// 如果信号量的值小于等于 0，则把当前进程放入 waitingThreads
    if (sem->value <= 0){
        Wait(&sem->waitingThreads);
    }
    
    sem->value--;

    return 0;
}

/* 信号量 V(释放)操作 */
int V(int sid) {
    // project3 V
    /* 错误中断 */
    KASSERT(sid > 0);

    pSemaphore sem = isSemExistBySID(sid);
    if (sem == NULL) {
        Print("Error! Connot Find Semaphore with SID=%d\n", sid);
        return -1;
    }

    int threadIndex = getIndexInRegThreadList(sem);
    if (threadIndex == -1) {
        Print("Error! Current Thread is not Using the Semaphore with SID=%d\n",
              sid);
        return -1;
    }

	// 如果信号量的值大于等于 1，则要唤醒一个正在等待此信号量的进程
    sem->value++;
    if (sem->value >= 1){
        Wake_Up_One(&sem->waitingThreads);
    }

    return 0;
}

/* 销毁一个信号量 */
int Destroy_Semaphore(int sid) {
    // project3 Destroy_Semaphore
    /* 错误中断 */
    KASSERT(sid > 0);

    pSemaphore sem = isSemExistBySID(sid);
    if (sem == NULL) {
        Print("Error! Connot Find Semaphore with SID=%d\n", sid);
        return -1;
    }

    int threadIndex = getIndexInRegThreadList(sem);
    if (threadIndex == -1) {
        Print("Error! Current Thread is not Using the Semaphore with SID=%d\n",
              sid);
        return -1;
    }

	// 在一个进程中删除一个信号量，所以 registeredThreadCount 要减 1，
	// 然后将 registeredThreads 列表中此线程之后的线程向前移动一位
    // 即在此列表中删除当前进程
    sem->registeredThreadCount--;
    int i;
    for (i = threadIndex; i < sem->registeredThreadCount; i++) {
        sem->registeredThreads[i] = sem->registeredThreads[i + 1];
    }
    sem->registeredThreads[sem->registeredThreadCount] = NULL;

	// 如果没有任何一个进程使用这个信号量，就删除此信号量
    if (sem->registeredThreadCount == 0) {
        /* 唤醒该信号量等待队列中所有线程 */
        Wake_Up(&sem->waitingThreads);
        Free(sem);
        Remove_From_Semaphore_List(&g_semList, sem);
        g_curSID--;
    }
    return 0;
}

/*
 * NOTES:
 * - The GeekOS mutex and condition variable APIs are based on those
 *   in pthreads.
 * - Unlike disabling interrupts, mutexes offer NO protection against
 *   concurrent execution of interrupt handlers.  Mutexes and
 *   condition variables should only be used from kernel threads,
 *   with interrupts enabled.
 */

/* ----------------------------------------------------------------------
 * Private functions
 * ---------------------------------------------------------------------- */

/*
 * The mutex is currently locked.
 * Atomically reenable preemption and wait in the
 * mutex's wait queue.
 */
static void Mutex_Wait(struct Mutex* mutex) {
    KASSERT(mutex->state == MUTEX_LOCKED);
    KASSERT(g_preemptionDisabled);

    Disable_Interrupts();
    g_preemptionDisabled = false;
    Wait(&mutex->waitQueue);
    g_preemptionDisabled = true;
    Enable_Interrupts();
}

/*
 * Lock given mutex.
 * Preemption must be disabled.
 */
static __inline__ void Mutex_Lock_Imp(struct Mutex* mutex) {
    KASSERT(g_preemptionDisabled);

    /* Make sure we're not already holding the mutex */
    KASSERT(!IS_HELD(mutex));

    /* Wait until the mutex is in an unlocked state */
    while (mutex->state == MUTEX_LOCKED) {
        Mutex_Wait(mutex);
    }

    /* Now it's ours! */
    mutex->state = MUTEX_LOCKED;
    mutex->owner = g_currentThread;
}

/*
 * Unlock given mutex.
 * Preemption must be disabled.
 */
static __inline__ void Mutex_Unlock_Imp(struct Mutex* mutex) {
    KASSERT(g_preemptionDisabled);

    /* Make sure mutex was actually acquired by this thread. */
    KASSERT(IS_HELD(mutex));

    /* Unlock the mutex. */
    mutex->state = MUTEX_UNLOCKED;
    mutex->owner = 0;

    /*
     * If there are threads waiting to acquire the mutex,
     * wake one of them up.  Note that it is legal to inspect
     * the queue with interrupts enabled because preemption
     * is disabled, and therefore we know that no thread can
     * concurrently add itself to the queue.
     */
    if (!Is_Thread_Queue_Empty(&mutex->waitQueue)) {
        Disable_Interrupts();
        Wake_Up_One(&mutex->waitQueue);
        Enable_Interrupts();
    }
}

/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */

/*
 * Initialize given mutex.
 */
void Mutex_Init(struct Mutex* mutex) {
    mutex->state = MUTEX_UNLOCKED;
    mutex->owner = 0;
    Clear_Thread_Queue(&mutex->waitQueue);
}

/*
 * Lock given mutex.
 */
void Mutex_Lock(struct Mutex* mutex) {
    KASSERT(Interrupts_Enabled());

    g_preemptionDisabled = true;
    Mutex_Lock_Imp(mutex);
    g_preemptionDisabled = false;
}

/*
 * Unlock given mutex.
 */
void Mutex_Unlock(struct Mutex* mutex) {
    KASSERT(Interrupts_Enabled());

    g_preemptionDisabled = true;
    Mutex_Unlock_Imp(mutex);
    g_preemptionDisabled = false;
}

/*
 * Initialize given condition.
 */
void Cond_Init(struct Condition* cond) {
    Clear_Thread_Queue(&cond->waitQueue);
}

/*
 * Wait on given condition (protected by given mutex).
 */
void Cond_Wait(struct Condition* cond, struct Mutex* mutex) {
    KASSERT(Interrupts_Enabled());

    /* Ensure mutex is held. */
    KASSERT(IS_HELD(mutex));

    /* Turn off scheduling. */
    g_preemptionDisabled = true;

    /*
     * Release the mutex, but leave preemption disabled.
     * No other threads will be able to run before this thread
     * is able to wait.  Therefore, this thread will not
     * miss the eventual notification on the condition.
     */
    Mutex_Unlock_Imp(mutex);

    /*
     * Atomically reenable preemption and wait in the condition wait queue.
     * Other threads can run while this thread is waiting,
     * and eventually one of them will call Cond_Signal() or Cond_Broadcast()
     * to wake up this thread.
     * On wakeup, disable preemption again.
     */
    Disable_Interrupts();
    g_preemptionDisabled = false;
    Wait(&cond->waitQueue);
    g_preemptionDisabled = true;
    Enable_Interrupts();

    /* Reacquire the mutex. */
    Mutex_Lock_Imp(mutex);

    /* Turn scheduling back on. */
    g_preemptionDisabled = false;
}

/*
 * Wake up one thread waiting on the given condition.
 * The mutex guarding the condition should be held!
 */
void Cond_Signal(struct Condition* cond) {
    KASSERT(Interrupts_Enabled());
    Disable_Interrupts(); /* prevent scheduling */
    Wake_Up_One(&cond->waitQueue);
    Enable_Interrupts(); /* resume scheduling */
}

/*
 * Wake up all threads waiting on the given condition.
 * The mutex guarding the condition should be held!
 */
void Cond_Broadcast(struct Condition* cond) {
    KASSERT(Interrupts_Enabled());
    Disable_Interrupts(); /* prevent scheduling */
    Wake_Up(&cond->waitQueue);
    Enable_Interrupts(); /* resume scheduling */
}
