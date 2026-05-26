#ifndef SREI_SYSCALL_H
#define SREI_SYSCALL_H

#include <stdint.h>
#include <stddef.h>

#define SYS_PROT_READ  1
#define SYS_PROT_WRITE 2
#define SYS_PROT_EXEC  4
#define SYS_PROT_NONE  0

#define SYS_MAP_PRIVATE   0x02
#define SYS_MAP_ANONYMOUS 0x20

#define SYS_MAP_FAILED ((void *)-1)

static inline long sys_mmap(void *addr, size_t len, long prot, long flags, long fd, long offset)
{
    long ret;
    register long r10 __asm__("r10") = flags;
    register long r8  __asm__("r8")  = fd;
    register long r9  __asm__("r9")  = offset;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"((uint64_t)9), "D"(addr), "S"(len), "d"(prot), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_mprotect(void *addr, size_t len, long prot)
{
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"((uint64_t)10), "D"(addr), "S"(len), "d"(prot)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_munmap(void *addr, size_t len)
{
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"((uint64_t)11), "D"(addr), "S"(len)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_write(long fd, const void *buf, size_t count)
{
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"((uint64_t)1), "D"(fd), "S"(buf), "d"(count)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline void sys_exit(long code)
{
    __asm__ volatile(
        "syscall"
        :
        : "a"((uint64_t)60), "D"(code)
        : "rcx", "r11", "memory"
    );
    __builtin_unreachable();
}

static inline long sys_open(const char *pathname, long flags, long mode)
{
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"((uint64_t)2), "D"(pathname), "S"(flags), "d"(mode)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_read(long fd, void *buf, size_t count)
{
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"((uint64_t)0), "D"(fd), "S"(buf), "d"(count)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_close(long fd)
{
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"((uint64_t)3), "D"(fd)
        : "rcx", "r11", "memory"
    );
    return ret;
}

#endif
