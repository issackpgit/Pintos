#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"

void syscall_init (void);
struct lock fs_lock;
//struct lock rox_lock;

#endif /* userprog/syscall.h */
