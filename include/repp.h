#ifndef _REPP_H
#define _REPP_H

#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <vector>
#include <map>
#include <string>
#include <functional>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/ucontext.h>

namespace Repp
{
    struct MemoryRegion
    {
        uintptr_t start;
        uintptr_t end;
        size_t size;
        int protection;
        std::string name;
        bool readable;
        bool writable;
        bool executable;
    };

    struct Module
    {
        std::string name;
        std::string path;
        uintptr_t base;
        size_t size;
        std::map<std::string, uintptr_t> exports;
    };

#if defined(__x86_64__)
    struct CpuContext
    {
        uint64_t rax, rbx, rcx, rdx;
        uint64_t rsi, rdi, rbp, rsp;
        uint64_t r8, r9, r10, r11;
        uint64_t r12, r13, r14, r15;
        uint64_t rip, rflags;

        uint64_t getReg(const std::string &name) const
        {
            if (name == "rax")
                return rax;
            if (name == "rbx")
                return rbx;
            if (name == "rcx")
                return rcx;
            if (name == "rdx")
                return rdx;
            if (name == "rsi")
                return rsi;
            if (name == "rdi")
                return rdi;
            if (name == "rbp")
                return rbp;
            if (name == "rsp")
                return rsp;
            if (name == "r8")
                return r8;
            if (name == "r9")
                return r9;
            if (name == "r10")
                return r10;
            if (name == "r11")
                return r11;
            if (name == "r12")
                return r12;
            if (name == "r13")
                return r13;
            if (name == "r14")
                return r14;
            if (name == "r15")
                return r15;
            if (name == "rip")
                return rip;
            if (name == "rflags")
                return rflags;
            return 0;
        }

        void setReg(const std::string &name, uint64_t value)
        {
            if (name == "rax")
                rax = value;
            else if (name == "rbx")
                rbx = value;
            else if (name == "rcx")
                rcx = value;
            else if (name == "rdx")
                rdx = value;
            else if (name == "rsi")
                rsi = value;
            else if (name == "rdi")
                rdi = value;
            else if (name == "rbp")
                rbp = value;
            else if (name == "rsp")
                rsp = value;
            else if (name == "r8")
                r8 = value;
            else if (name == "r9")
                r9 = value;
            else if (name == "r10")
                r10 = value;
            else if (name == "r11")
                r11 = value;
            else if (name == "r12")
                r12 = value;
            else if (name == "r13")
                r13 = value;
            else if (name == "r14")
                r14 = value;
            else if (name == "r15")
                r15 = value;
            else if (name == "rip")
                rip = value;
            else if (name == "rflags")
                rflags = value;
        }
    };
#elif defined(__i386__)
    struct CpuContext
    {
        uint32_t eax, ebx, ecx, edx;
        uint32_t esi, edi, ebp, esp;
        uint32_t eip, eflags;

        uint32_t getReg(const std::string &name) const
        {
            if (name == "eax")
                return eax;
            if (name == "ebx")
                return ebx;
            if (name == "ecx")
                return ecx;
            if (name == "edx")
                return edx;
            if (name == "esi")
                return esi;
            if (name == "edi")
                return edi;
            if (name == "ebp")
                return ebp;
            if (name == "esp")
                return esp;
            if (name == "eip")
                return eip;
            if (name == "eflags")
                return eflags;
            return 0;
        }

        void setReg(const std::string &name, uint32_t value)
        {
            if (name == "eax")
                eax = value;
            else if (name == "ebx")
                ebx = value;
            else if (name == "ecx")
                ecx = value;
            else if (name == "edx")
                edx = value;
            else if (name == "esi")
                esi = value;
            else if (name == "edi")
                edi = value;
            else if (name == "ebp")
                ebp = value;
            else if (name == "esp")
                esp = value;
            else if (name == "eip")
                eip = value;
            else if (name == "eflags")
                eflags = value;
        }
    };
#elif defined(__aarch64__)
    struct CpuContext
    {
        uint64_t x[31];
        uint64_t sp, pc, pstate;

        uint64_t getReg(const std::string &name) const
        {
            if (name.substr(0, 1) == "x" && name.length() <= 3)
            {
                int regNum = std::stoi(name.substr(1));
                if (regNum >= 0 && regNum <= 30)
                    return x[regNum];
            }
            if (name == "sp")
                return sp;
            if (name == "pc")
                return pc;
            if (name == "pstate")
                return pstate;
            return 0;
        }

        void setReg(const std::string &name, uint64_t value)
        {
            if (name.substr(0, 1) == "x" && name.length() <= 3)
            {
                int regNum = std::stoi(name.substr(1));
                if (regNum >= 0 && regNum <= 30)
                    x[regNum] = value;
            }
            else if (name == "sp")
                sp = value;
            else if (name == "pc")
                pc = value;
            else if (name == "pstate")
                pstate = value;
        }
    };
#elif defined(__arm__)
    struct CpuContext
    {
        uint32_t r[13];
        uint32_t sp, lr, pc, cpsr;

        uint32_t getReg(const std::string &name) const
        {
            if (name.substr(0, 1) == "r" && name.length() <= 3)
            {
                int regNum = std::stoi(name.substr(1));
                if (regNum >= 0 && regNum <= 12)
                    return r[regNum];
            }
            if (name == "sp")
                return sp;
            if (name == "lr")
                return lr;
            if (name == "pc")
                return pc;
            if (name == "cpsr")
                return cpsr;
            return 0;
        }

        void setReg(const std::string &name, uint32_t value)
        {
            if (name.substr(0, 1) == "r" && name.length() <= 3)
            {
                int regNum = std::stoi(name.substr(1));
                if (regNum >= 0 && regNum <= 12)
                    r[regNum] = value;
            }
            else if (name == "sp")
                sp = value;
            else if (name == "lr")
                lr = value;
            else if (name == "pc")
                pc = value;
            else if (name == "cpsr")
                cpsr = value;
        }
    };
#endif

    typedef std::function<void(CpuContext *)> OnEnterCallback;
    typedef std::function<void(CpuContext *)> OnLeaveCallback;

    struct Interceptor
    {
        uintptr_t target;
        OnEnterCallback onEnter;
        OnLeaveCallback onLeave;
        bool enabled;
    };

    struct HookContext
    {
        char *targetAddress;
        char *replacementFunction;
        char *trampoline;
        uint8_t originalBytes[32];
        size_t patchSize;
        bool isHooked;
        CpuContext savedContext;
    };

    static std::map<uintptr_t, Interceptor> g_interceptors;
    static thread_local CpuContext *g_currentContext = nullptr;

    static void captureContext(CpuContext *ctx)
    {
#if defined(__x86_64__)
        asm volatile(
            "movq %%rax, %0\n"
            "movq %%rbx, %1\n"
            "movq %%rcx, %2\n"
            "movq %%rdx, %3\n"
            "movq %%rsi, %4\n"
            "movq %%rdi, %5\n"
            "movq %%rbp, %6\n"
            "movq %%rsp, %7\n"
            "movq %%r8, %8\n"
            "movq %%r9, %9\n"
            "movq %%r10, %10\n"
            "movq %%r11, %11\n"
            "movq %%r12, %12\n"
            "movq %%r13, %13\n"
            "movq %%r14, %14\n"
            "movq %%r15, %15\n"
            "pushfq\n"
            "popq %16\n"
            : "=m"(ctx->rax), "=m"(ctx->rbx), "=m"(ctx->rcx), "=m"(ctx->rdx),
              "=m"(ctx->rsi), "=m"(ctx->rdi), "=m"(ctx->rbp), "=m"(ctx->rsp),
              "=m"(ctx->r8), "=m"(ctx->r9), "=m"(ctx->r10), "=m"(ctx->r11),
              "=m"(ctx->r12), "=m"(ctx->r13), "=m"(ctx->r14), "=m"(ctx->r15),
              "=m"(ctx->rflags));
#elif defined(__i386__)
        asm volatile(
            "movl %%eax, %0\n"
            "movl %%ebx, %1\n"
            "movl %%ecx, %2\n"
            "movl %%edx, %3\n"
            "movl %%esi, %4\n"
            "movl %%edi, %5\n"
            "movl %%ebp, %6\n"
            "movl %%esp, %7\n"
            "pushfl\n"
            "popl %8\n"
            : "=m"(ctx->eax), "=m"(ctx->ebx), "=m"(ctx->ecx), "=m"(ctx->edx),
              "=m"(ctx->esi), "=m"(ctx->edi), "=m"(ctx->ebp), "=m"(ctx->esp),
              "=m"(ctx->eflags));
#elif defined(__aarch64__)
        asm volatile(
            "stp x0, x1, [%0, #0]\n"
            "stp x2, x3, [%0, #16]\n"
            "stp x4, x5, [%0, #32]\n"
            "stp x6, x7, [%0, #48]\n"
            "stp x8, x9, [%0, #64]\n"
            "stp x10, x11, [%0, #80]\n"
            "stp x12, x13, [%0, #96]\n"
            "stp x14, x15, [%0, #112]\n"
            "stp x16, x17, [%0, #128]\n"
            "stp x18, x19, [%0, #144]\n"
            "stp x20, x21, [%0, #160]\n"
            "stp x22, x23, [%0, #176]\n"
            "stp x24, x25, [%0, #192]\n"
            "stp x26, x27, [%0, #208]\n"
            "stp x28, x29, [%0, #224]\n"
            "str x30, [%0, #240]\n"
            "mov x1, sp\n"
            "str x1, [%0, #248]\n"
            :
            : "r"(ctx->x)
            : "x1", "memory");
#elif defined(__arm__)
        asm volatile(
            "str r0, [%0, #0]\n"
            "str r1, [%0, #4]\n"
            "str r2, [%0, #8]\n"
            "str r3, [%0, #12]\n"
            "str r4, [%0, #16]\n"
            "str r5, [%0, #20]\n"
            "str r6, [%0, #24]\n"
            "str r7, [%0, #28]\n"
            "str r8, [%0, #32]\n"
            "str r9, [%0, #36]\n"
            "str r10, [%0, #40]\n"
            "str r11, [%0, #44]\n"
            "str r12, [%0, #48]\n"
            "str sp, [%0, #52]\n"
            "str lr, [%0, #56]\n"
            :
            : "r"(ctx->r)
            : "memory");
#endif
    }

    static void restoreContext(const CpuContext *ctx)
    {
#if defined(__x86_64__)
        asm volatile(
            "movq %0, %%rax\n"
            "movq %1, %%rbx\n"
            "movq %2, %%rcx\n"
            "movq %3, %%rdx\n"
            "movq %4, %%rsi\n"
            "movq %5, %%rdi\n"
            "movq %6, %%rbp\n"
            "movq %7, %%rsp\n"
            "movq %8, %%r8\n"
            "movq %9, %%r9\n"
            "movq %10, %%r10\n"
            "movq %11, %%r11\n"
            "movq %12, %%r12\n"
            "movq %13, %%r13\n"
            "movq %14, %%r14\n"
            "movq %15, %%r15\n"
            "pushq %16\n"
            "popfq\n"
            :
            : "m"(ctx->rax), "m"(ctx->rbx), "m"(ctx->rcx), "m"(ctx->rdx),
              "m"(ctx->rsi), "m"(ctx->rdi), "m"(ctx->rbp), "m"(ctx->rsp),
              "m"(ctx->r8), "m"(ctx->r9), "m"(ctx->r10), "m"(ctx->r11),
              "m"(ctx->r12), "m"(ctx->r13), "m"(ctx->r14), "m"(ctx->r15),
              "m"(ctx->rflags));
#elif defined(__i386__)
        asm volatile(
            "movl %0, %%eax\n"
            "movl %1, %%ebx\n"
            "movl %2, %%ecx\n"
            "movl %3, %%edx\n"
            "movl %4, %%esi\n"
            "movl %5, %%edi\n"
            "movl %6, %%ebp\n"
            "movl %7, %%esp\n"
            "pushl %8\n"
            "popfl\n"
            :
            : "m"(ctx->eax), "m"(ctx->ebx), "m"(ctx->ecx), "m"(ctx->edx),
              "m"(ctx->esi), "m"(ctx->edi), "m"(ctx->ebp), "m"(ctx->esp),
              "m"(ctx->eflags));
#elif defined(__aarch64__)
        asm volatile(
            "ldp x0, x1, [%0, #0]\n"
            "ldp x2, x3, [%0, #16]\n"
            "ldp x4, x5, [%0, #32]\n"
            "ldp x6, x7, [%0, #48]\n"
            "ldp x8, x9, [%0, #64]\n"
            "ldp x10, x11, [%0, #80]\n"
            "ldp x12, x13, [%0, #96]\n"
            "ldp x14, x15, [%0, #112]\n"
            "ldp x16, x17, [%0, #128]\n"
            "ldp x18, x19, [%0, #144]\n"
            "ldp x20, x21, [%0, #160]\n"
            "ldp x22, x23, [%0, #176]\n"
            "ldp x24, x25, [%0, #192]\n"
            "ldp x26, x27, [%0, #208]\n"
            "ldp x28, x29, [%0, #224]\n"
            "ldr x30, [%0, #240]\n"
            "ldr x1, [%0, #248]\n"
            "mov sp, x1\n"
            :
            : "r"(ctx->x)
            : "x1", "memory");
#elif defined(__arm__)
        asm volatile(
            "ldr r0, [%0, #0]\n"
            "ldr r1, [%0, #4]\n"
            "ldr r2, [%0, #8]\n"
            "ldr r3, [%0, #12]\n"
            "ldr r4, [%0, #16]\n"
            "ldr r5, [%0, #20]\n"
            "ldr r6, [%0, #24]\n"
            "ldr r7, [%0, #28]\n"
            "ldr r8, [%0, #32]\n"
            "ldr r9, [%0, #36]\n"
            "ldr r10, [%0, #40]\n"
            "ldr r11, [%0, #44]\n"
            "ldr r12, [%0, #48]\n"
            "ldr sp, [%0, #52]\n"
            "ldr lr, [%0, #56]\n"
            :
            : "r"(ctx->r)
            : "memory");
#endif
    }

    static CpuContext *getCurrentContext()
    {
        return g_currentContext;
    }

    static char *getPageStart(char *addr)
    {
        return (char *)((uintptr_t)addr & ~(getpagesize() - 1));
    }

    static bool makeWritable(char *addr)
    {
        char *pageStart = getPageStart(addr);
        return mprotect(pageStart, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
    }

    static void clearCache(char *addr, size_t size)
    {
        __builtin___clear_cache(addr, addr + size);
    }

    static char *allocateTrampoline()
    {
        char *page = (char *)mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED)
        {
            return nullptr;
        }
        return page;
    }

    static void hookTrampoline()
    {
        CpuContext ctx;
        captureContext(&ctx);
        g_currentContext = &ctx;

        auto it = g_interceptors.find(reinterpret_cast<uintptr_t>(__builtin_return_address(0)));
        if (it != g_interceptors.end() && it->second.enabled)
        {
            if (it->second.onEnter)
            {
                it->second.onEnter(&ctx);
            }
        }

        restoreContext(&ctx);
        g_currentContext = nullptr;
    }

    static bool writeAbsoluteJump(char *target, char *destination, HookContext *ctx)
    {
#if defined(__i386__)
        uint8_t *p = reinterpret_cast<uint8_t *>(target);
        ctx->patchSize = 5;
        memcpy(ctx->originalBytes, p, ctx->patchSize);
        p[0] = 0xE9;
        *reinterpret_cast<uint32_t *>(p + 1) = reinterpret_cast<uintptr_t>(destination) - reinterpret_cast<uintptr_t>(target) - 5;
#elif defined(__x86_64__)
        uint8_t *p = reinterpret_cast<uint8_t *>(target);
        ctx->patchSize = 14;
        memcpy(ctx->originalBytes, p, ctx->patchSize);
        p[0] = 0xFF;
        p[1] = 0x25;
        *reinterpret_cast<uint32_t *>(p + 2) = 0;
        *reinterpret_cast<uint64_t *>(p + 6) = reinterpret_cast<uint64_t>(destination);
#elif defined(__arm__)
        uint8_t *p = reinterpret_cast<uint8_t *>(target);
        ctx->patchSize = 8;
        memcpy(ctx->originalBytes, p, ctx->patchSize);
        p[0] = 0x04;
        p[1] = 0xf0;
        p[2] = 0x1f;
        p[3] = 0xe5;
        *reinterpret_cast<uint32_t *>(p + 4) = reinterpret_cast<uint32_t>(destination);
#elif defined(__aarch64__)
        uint32_t *code = reinterpret_cast<uint32_t *>(target);
        ctx->patchSize = 12;
        memcpy(ctx->originalBytes, code, ctx->patchSize);
        code[0] = 0x58000050;
        code[1] = 0xD61F0200;
        reinterpret_cast<uint64_t *>(code)[1] = reinterpret_cast<uint64_t>(destination);
#else
        return false;
#endif
        clearCache(target, ctx->patchSize);
        return true;
    }

    static int installHook(HookContext *ctx, char *target, char *replacement)
    {
        if (!ctx || !target || !replacement)
        {
            return 1;
        }

        ctx->targetAddress = target;
        ctx->replacementFunction = replacement;
        ctx->isHooked = false;

        if (!makeWritable(target))
        {
            return 2;
        }

        if (!writeAbsoluteJump(target, replacement, ctx))
        {
            return 3;
        }

        ctx->isHooked = true;
        return 0;
    }

    static int removeHook(HookContext *ctx)
    {
        if (!ctx || !ctx->isHooked)
        {
            return 1;
        }

        if (!makeWritable(ctx->targetAddress))
        {
            return 2;
        }

        memcpy(ctx->targetAddress, ctx->originalBytes, ctx->patchSize);
        clearCache(ctx->targetAddress, ctx->patchSize);
        ctx->isHooked = false;
        return 0;
    }

    template <typename Func, typename... Args>
    static auto callOriginal(HookContext *ctx, Func originalFunc, Args... args) -> decltype(originalFunc(args...))
    {
        if (!ctx || !ctx->isHooked)
        {
            return originalFunc(args...);
        }

        removeHook(ctx);

        if constexpr (std::is_void_v<decltype(originalFunc(args...))>)
        {
            originalFunc(args...);
            installHook(ctx, ctx->targetAddress, ctx->replacementFunction);
        }
        else
        {
            auto result = originalFunc(args...);
            installHook(ctx, ctx->targetAddress, ctx->replacementFunction);
            return result;
        }
    }

    template <typename Func, typename... Args>
    static auto callOriginal(Func originalFunc, Args... args) -> decltype(originalFunc(args...))
    {
        return originalFunc(args...);
    }

    static char *getModuleBase(const char *name)
    {
        FILE *fp = fopen("/proc/self/maps", "r");
        if (!fp)
        {
            return nullptr;
        }

        char line[512];
        char *base = nullptr;
        while (fgets(line, sizeof(line), fp))
        {
            if (strstr(line, name))
            {
                uintptr_t addr;
                sscanf(line, "%lx-%*s", &addr);
                base = (char *)addr;
                break;
            }
        }

        fclose(fp);
        return base;
    }

    static char *getExportByName(const char *module, const char *symbol)
    {
        char *base = getModuleBase(module);
        if (!base)
        {
            return nullptr;
        }

        int fd = open(module, O_RDONLY);
        if (fd < 0)
        {
            return nullptr;
        }

        struct stat st;
        if (fstat(fd, &st) != 0)
        {
            close(fd);
            return nullptr;
        }

        char *map = (char *)mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (map == MAP_FAILED)
        {
            return nullptr;
        }

#if defined(__LP64__)
        Elf64_Ehdr *ehdr = reinterpret_cast<Elf64_Ehdr *>(map);
        Elf64_Shdr *shdr = reinterpret_cast<Elf64_Shdr *>(map + ehdr->e_shoff);
        const char *strtab = nullptr;
        Elf64_Sym *symtab = nullptr;
        size_t symcount = 0;

        for (int i = 0; i < ehdr->e_shnum; ++i)
        {
            if (shdr[i].sh_type == SHT_STRTAB && i != ehdr->e_shstrndx)
            {
                strtab = map + shdr[i].sh_offset;
            }
            else if (shdr[i].sh_type == SHT_DYNSYM)
            {
                symtab = reinterpret_cast<Elf64_Sym *>(map + shdr[i].sh_offset);
                symcount = shdr[i].sh_size / sizeof(Elf64_Sym);
            }
        }

        char *result = nullptr;
        if (symtab && strtab)
        {
            for (size_t i = 0; i < symcount; ++i)
            {
                if (strcmp(strtab + symtab[i].st_name, symbol) == 0)
                {
                    result = base + symtab[i].st_value;
                    break;
                }
            }
        }
#else
        Elf32_Ehdr *ehdr = reinterpret_cast<Elf32_Ehdr *>(map);
        Elf32_Shdr *shdr = reinterpret_cast<Elf32_Shdr *>(map + ehdr->e_shoff);
        const char *strtab = nullptr;
        Elf32_Sym *symtab = nullptr;
        size_t symcount = 0;

        for (int i = 0; i < ehdr->e_shnum; ++i)
        {
            if (shdr[i].sh_type == SHT_STRTAB && i != ehdr->e_shstrndx)
            {
                strtab = map + shdr[i].sh_offset;
            }
            else if (shdr[i].sh_type == SHT_DYNSYM)
            {
                symtab = reinterpret_cast<Elf32_Sym *>(map + shdr[i].sh_offset);
                symcount = shdr[i].sh_size / sizeof(Elf32_Sym);
            }
        }

        char *result = nullptr;
        if (symtab && strtab)
        {
            for (size_t i = 0; i < symcount; ++i)
            {
                if (strcmp(strtab + symtab[i].st_name, symbol) == 0)
                {
                    result = base + symtab[i].st_value;
                    break;
                }
            }
        }
#endif

        munmap(map, st.st_size);
        return result;
    }

    static int patchString(char *addr, const char *replacement)
    {
        char *target = addr;
        size_t len = strlen(replacement) + 1;

        size_t pageSize = static_cast<size_t>(getpagesize());
        uintptr_t start = reinterpret_cast<uintptr_t>(target) & ~(pageSize - 1);
        uintptr_t end = (reinterpret_cast<uintptr_t>(target) + len - 1) & ~(pageSize - 1);
        size_t size = (end - start) + pageSize;

        if (mprotect((char *)start, size, PROT_READ | PROT_WRITE) != 0)
        {
            return 1;
        }

        memcpy(target, replacement, len);
        clearCache(target, len);

        return 0;
    }

    static bool protectMemory(uintptr_t address, size_t size, int protection)
    {
        size_t pageSize = static_cast<size_t>(getpagesize());
        uintptr_t start = address & ~(pageSize - 1);
        uintptr_t end = (address + size - 1) & ~(pageSize - 1);
        size_t totalSize = (end - start) + pageSize;

        return mprotect(reinterpret_cast<void *>(start), totalSize, protection) == 0;
    }

    static uintptr_t allocateMemory(size_t size, int protection = PROT_READ | PROT_WRITE)
    {
        void *ptr = mmap(nullptr, size, protection, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return (ptr == MAP_FAILED) ? 0 : reinterpret_cast<uintptr_t>(ptr);
    }

    static bool freeMemory(uintptr_t address, size_t size)
    {
        return munmap(reinterpret_cast<void *>(address), size) == 0;
    }

    template <typename T>
    static T readMemory(uintptr_t address)
    {
        return *reinterpret_cast<T *>(address);
    }

    static uint8_t readU8(uintptr_t address) { return readMemory<uint8_t>(address); }
    static uint16_t readU16(uintptr_t address) { return readMemory<uint16_t>(address); }
    static uint32_t readU32(uintptr_t address) { return readMemory<uint32_t>(address); }
    static uint64_t readU64(uintptr_t address) { return readMemory<uint64_t>(address); }
    static int8_t readS8(uintptr_t address) { return readMemory<int8_t>(address); }
    static int16_t readS16(uintptr_t address) { return readMemory<int16_t>(address); }
    static int32_t readS32(uintptr_t address) { return readMemory<int32_t>(address); }
    static int64_t readS64(uintptr_t address) { return readMemory<int64_t>(address); }
    static float readFloat(uintptr_t address) { return readMemory<float>(address); }
    static double readDouble(uintptr_t address) { return readMemory<double>(address); }
    static uintptr_t readPointer(uintptr_t address) { return readMemory<uintptr_t>(address); }

    template <typename T>
    static bool writeMemory(uintptr_t address, T value)
    {
        if (!protectMemory(address, sizeof(T), PROT_READ | PROT_WRITE))
            return false;

        *reinterpret_cast<T *>(address) = value;
        clearCache(reinterpret_cast<char *>(address), sizeof(T));
        return true;
    }

    static bool writeU8(uintptr_t address, uint8_t value) { return writeMemory(address, value); }
    static bool writeU16(uintptr_t address, uint16_t value) { return writeMemory(address, value); }
    static bool writeU32(uintptr_t address, uint32_t value) { return writeMemory(address, value); }
    static bool writeU64(uintptr_t address, uint64_t value) { return writeMemory(address, value); }
    static bool writeS8(uintptr_t address, int8_t value) { return writeMemory(address, value); }
    static bool writeS16(uintptr_t address, int16_t value) { return writeMemory(address, value); }
    static bool writeS32(uintptr_t address, int32_t value) { return writeMemory(address, value); }
    static bool writeS64(uintptr_t address, int64_t value) { return writeMemory(address, value); }
    static bool writeFloat(uintptr_t address, float value) { return writeMemory(address, value); }
    static bool writeDouble(uintptr_t address, double value) { return writeMemory(address, value); }
    static bool writePointer(uintptr_t address, uintptr_t value) { return writeMemory(address, value); }

    static bool writeBytes(uintptr_t address, const uint8_t *data, size_t size)
    {
        if (!protectMemory(address, size, PROT_READ | PROT_WRITE))
            return false;

        memcpy(reinterpret_cast<void *>(address), data, size);
        clearCache(reinterpret_cast<char *>(address), size);
        return true;
    }

    static bool readBytes(uintptr_t address, uint8_t *buffer, size_t size)
    {
        memcpy(buffer, reinterpret_cast<const void *>(address), size);
        return true;
    }

    static std::string readString(uintptr_t address, size_t maxLength = 1024)
    {
        std::string result;
        const char *str = reinterpret_cast<const char *>(address);

        for (size_t i = 0; i < maxLength; ++i)
        {
            if (str[i] == '\0')
                break;
            result += str[i];
        }
        return result;
    }

    static bool writeString(uintptr_t address, const std::string &str)
    {
        return writeBytes(address, reinterpret_cast<const uint8_t *>(str.c_str()), str.length() + 1);
    }

    static std::vector<uintptr_t> scanMemory(uintptr_t startAddr, uintptr_t endAddr,
                                             const uint8_t *pattern, size_t patternSize)
    {
        std::vector<uintptr_t> results;

        for (uintptr_t addr = startAddr; addr <= endAddr - patternSize; ++addr)
        {
            if (memcmp(reinterpret_cast<const void *>(addr), pattern, patternSize) == 0)
            {
                results.push_back(addr);
            }
        }
        return results;
    }

    static std::vector<MemoryRegion> enumerateMemoryRegions()
    {
        std::vector<MemoryRegion> regions;
        FILE *fp = fopen("/proc/self/maps", "r");
        if (!fp)
            return regions;

        char line[512];
        while (fgets(line, sizeof(line), fp))
        {
            MemoryRegion region;
            uintptr_t start, end;
            char perms[5];

            if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3)
            {
                region.start = start;
                region.end = end;
                region.size = end - start;
                region.readable = (perms[0] == 'r');
                region.writable = (perms[1] == 'w');
                region.executable = (perms[2] == 'x');

                region.protection = 0;
                if (region.readable)
                    region.protection |= PROT_READ;
                if (region.writable)
                    region.protection |= PROT_WRITE;
                if (region.executable)
                    region.protection |= PROT_EXEC;

                char *nameStart = strrchr(line, '/');
                if (nameStart)
                {
                    region.name = std::string(nameStart + 1);
                    region.name.erase(region.name.find_last_not_of(" \n\r\t") + 1);
                }

                regions.push_back(region);
            }
        }

        fclose(fp);
        return regions;
    }

    static std::vector<Module> enumerateModules()
    {
        std::vector<Module> modules;
        std::vector<MemoryRegion> regions = enumerateMemoryRegions();

        std::map<std::string, Module> moduleMap;

        for (const auto &region : regions)
        {
            if (!region.name.empty() && region.executable)
            {
                if (moduleMap.find(region.name) == moduleMap.end())
                {
                    Module module;
                    module.name = region.name;
                    module.base = region.start;
                    module.size = region.size;
                    moduleMap[region.name] = module;
                }
            }
        }

        for (auto &pair : moduleMap)
        {
            modules.push_back(pair.second);
        }

        return modules;
    }

    static uintptr_t findSymbol(const std::string &moduleName, const std::string &symbolName)
    {
        char *addr = getExportByName(moduleName.c_str(), symbolName.c_str());
        return reinterpret_cast<uintptr_t>(addr);
    }

    static bool attach(uintptr_t target, OnEnterCallback onEnter, OnLeaveCallback onLeave = nullptr)
    {
        Interceptor interceptor;
        interceptor.target = target;
        interceptor.onEnter = onEnter;
        interceptor.onLeave = onLeave;
        interceptor.enabled = true;

        g_interceptors[target] = interceptor;

        HookContext *ctx = new HookContext();
        return installHook(ctx, reinterpret_cast<char *>(target), reinterpret_cast<char *>(hookTrampoline)) == 0;
    }

    static bool detach(uintptr_t target)
    {
        auto it = g_interceptors.find(target);
        if (it != g_interceptors.end())
        {
            g_interceptors.erase(it);
            return true;
        }
        return false;
    }

    static std::vector<int> enumerateProcesses()
    {
        std::vector<int> pids;
        DIR *proc = opendir("/proc");
        if (!proc)
            return pids;

        struct dirent *entry;
        while ((entry = readdir(proc)) != nullptr)
        {
            if (entry->d_type == DT_DIR)
            {
                int pid = atoi(entry->d_name);
                if (pid > 0)
                {
                    pids.push_back(pid);
                }
            }
        }

        closedir(proc);
        return pids;
    }

    static uintptr_t getModuleBaseAddress(const std::string &moduleName)
    {
        char *base = getModuleBase(moduleName.c_str());
        return reinterpret_cast<uintptr_t>(base);
    }

    static size_t getModuleSize(const std::string &moduleName)
    {
        std::vector<Module> modules = enumerateModules();
        for (const auto &module : modules)
        {
            if (module.name == moduleName)
            {
                return module.size;
            }
        }
        return 0;
    }

    template <typename T>
    static T getRegister(const std::string &regName)
    {
        CpuContext *ctx = getCurrentContext();
        if (!ctx)
            return T{};

#if defined(__x86_64__)
        return static_cast<T>(ctx->getReg(regName));
#elif defined(__i386__)
        return static_cast<T>(ctx->getReg(regName));
#elif defined(__aarch64__)
        return static_cast<T>(ctx->getReg(regName));
#elif defined(__arm__)
        return static_cast<T>(ctx->getReg(regName));
#endif
        return T{};
    }

    template <typename T>
    static void setRegister(const std::string &regName, T value)
    {
        CpuContext *ctx = getCurrentContext();
        if (!ctx)
            return;

#if defined(__x86_64__)
        ctx->setReg(regName, static_cast<uint64_t>(value));
#elif defined(__i386__)
        ctx->setReg(regName, static_cast<uint32_t>(value));
#elif defined(__aarch64__)
        ctx->setReg(regName, static_cast<uint64_t>(value));
#elif defined(__arm__)
        ctx->setReg(regName, static_cast<uint32_t>(value));
#endif
    }

    static uintptr_t getReturnValue()
    {
#if defined(__x86_64__)
        return getRegister<uintptr_t>("rax");
#elif defined(__i386__)
        return getRegister<uintptr_t>("eax");
#elif defined(__aarch64__)
        return getRegister<uintptr_t>("x0");
#elif defined(__arm__)
        return getRegister<uintptr_t>("r0");
#endif
        return 0;
    }

    static void setReturnValue(uintptr_t value)
    {
#if defined(__x86_64__)
        setRegister("rax", value);
#elif defined(__i386__)
        setRegister("eax", value);
#elif defined(__aarch64__)
        setRegister("x0", value);
#elif defined(__arm__)
        setRegister("r0", value);
#endif
    }

    static uintptr_t getArgument(int index)
    {
#if defined(__x86_64__)
        switch (index)
        {
        case 0:
            return getRegister<uintptr_t>("rdi");
        case 1:
            return getRegister<uintptr_t>("rsi");
        case 2:
            return getRegister<uintptr_t>("rdx");
        case 3:
            return getRegister<uintptr_t>("rcx");
        case 4:
            return getRegister<uintptr_t>("r8");
        case 5:
            return getRegister<uintptr_t>("r9");
        default:
        {
            uintptr_t rsp = getRegister<uintptr_t>("rsp");
            return readPointer(rsp + (index - 6 + 1) * 8);
        }
        }
#elif defined(__i386__)
        uintptr_t esp = getRegister<uintptr_t>("esp");
        return readPointer(esp + (index + 1) * 4);
#elif defined(__aarch64__)
        if (index < 8)
        {
            return getRegister<uintptr_t>("x" + std::to_string(index));
        }
        else
        {
            uintptr_t sp = getRegister<uintptr_t>("sp");
            return readPointer(sp + (index - 8) * 8);
        }
#elif defined(__arm__)
        if (index < 4)
        {
            return getRegister<uintptr_t>("r" + std::to_string(index));
        }
        else
        {
            uintptr_t sp = getRegister<uintptr_t>("sp");
            return readPointer(sp + (index - 4) * 4);
        }
#endif
        return 0;
    }

    static void setArgument(int index, uintptr_t value)
    {
#if defined(__x86_64__)
        switch (index)
        {
        case 0:
            setRegister("rdi", value);
            break;
        case 1:
            setRegister("rsi", value);
            break;
        case 2:
            setRegister("rdx", value);
            break;
        case 3:
            setRegister("rcx", value);
            break;
        case 4:
            setRegister("r8", value);
            break;
        case 5:
            setRegister("r9", value);
            break;
        default:
        {
            uintptr_t rsp = getRegister<uintptr_t>("rsp");
            writePointer(rsp + (index - 6 + 1) * 8, value);
            break;
        }
        }
#elif defined(__i386__)
        uintptr_t esp = getRegister<uintptr_t>("esp");
        writePointer(esp + (index + 1) * 4, value);
#elif defined(__aarch64__)
        if (index < 8)
        {
            setRegister("x" + std::to_string(index), value);
        }
        else
        {
            uintptr_t sp = getRegister<uintptr_t>("sp");
            writePointer(sp + (index - 8) * 8, value);
        }
#elif defined(__arm__)
        if (index < 4)
        {
            setRegister("r" + std::to_string(index), value);
        }
        else
        {
            uintptr_t sp = getRegister<uintptr_t>("sp");
            writePointer(sp + (index - 4) * 4, value);
        }
#endif
    }

    static void skipFunction(uintptr_t target, uintptr_t returnValue = 0)
    {
        attach(target, [returnValue](CpuContext *ctx)
               {
                   setReturnValue(returnValue);
#if defined(__x86_64__)
                   uintptr_t retAddr = readPointer(ctx->rsp);
                   ctx->rsp += 8;
                   ctx->rip = retAddr;
#elif defined(__i386__)
                   uintptr_t retAddr = readPointer(ctx->esp);
                   ctx->esp += 4;
                   ctx->eip = retAddr;
#elif defined(__aarch64__)
                   ctx->pc = ctx->x[30];
#elif defined(__arm__)
                   ctx->pc = ctx->lr;
#endif
               });
    }

    struct StackFrame
    {
        uintptr_t address;
        std::string symbol;
        std::string module;
        uintptr_t offset;
    };

    static bool isValidAddress(uintptr_t addr)
    {
        // Check if address is in valid memory range
        std::vector<MemoryRegion> regions = enumerateMemoryRegions();
        for (const auto &region : regions)
        {
            if (addr >= region.start && addr < region.end)
                return true;
        }
        return false;
    }

    static bool safeRead(uintptr_t addr, uintptr_t &value)
    {
        if (!isValidAddress(addr))
            return false;

        try
        {
            value = readPointer(addr);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    static void resolveSymbol(StackFrame &frame)
    {
        frame.symbol = "unknown";
        frame.module = "unknown";
        frame.offset = 0;

        std::vector<Module> modules = enumerateModules();
        for (const auto &module : modules)
        {
            if (frame.address >= module.base && frame.address < module.base + module.size)
            {
                frame.module = module.name;
                frame.offset = frame.address - module.base;

                Dl_info info;
                if (dladdr(reinterpret_cast<void *>(frame.address), &info))
                {
                    if (info.dli_sname)
                    {
                        frame.symbol = info.dli_sname;
                        frame.offset = frame.address - reinterpret_cast<uintptr_t>(info.dli_saddr);
                    }
                }
                break;
            }
        }
    }

    static std::vector<StackFrame> getCurrentStackTrace(size_t maxFrames = 64)
    {
        std::vector<StackFrame> frames;

        uintptr_t framePointer;

#if defined(__x86_64__)
        asm volatile("movq %%rbp, %0" : "=r"(framePointer));
#elif defined(__i386__)
        asm volatile("movl %%ebp, %0" : "=r"(framePointer));
#elif defined(__aarch64__)
        asm volatile("mov %0, x29" : "=r"(framePointer));
#elif defined(__arm__)
        asm volatile("mov %0, r11" : "=r"(framePointer));
#endif

        size_t frameCount = 0;
        uintptr_t currentFP = framePointer;

        while (frameCount < maxFrames && currentFP != 0 && isValidAddress(currentFP))
        {
            uintptr_t nextFP, returnAddr;

            if (!safeRead(currentFP, nextFP) || !safeRead(currentFP + sizeof(uintptr_t), returnAddr))
                break;

            if (returnAddr == 0 || !isValidAddress(returnAddr))
                break;

            StackFrame frame;
            frame.address = returnAddr;
            resolveSymbol(frame);
            frames.push_back(frame);

            currentFP = nextFP;
            frameCount++;

            if (nextFP <= currentFP)
                break;
        }

        return frames;
    }

    static std::vector<StackFrame> getStackTrace(size_t maxFrames = 64)
    {
        std::vector<StackFrame> frames;
        CpuContext *ctx = getCurrentContext();

        if (!ctx)
        {
            return getCurrentStackTrace(maxFrames);
        }

        uintptr_t framePointer, stackPointer, instructionPointer;

#if defined(__x86_64__)
        framePointer = ctx->rbp;
        stackPointer = ctx->rsp;
        instructionPointer = ctx->rip;
#elif defined(__i386__)
        framePointer = ctx->ebp;
        stackPointer = ctx->esp;
        instructionPointer = ctx->eip;
#elif defined(__aarch64__)
        framePointer = ctx->x[29];
        stackPointer = ctx->sp;
        instructionPointer = ctx->pc;
#elif defined(__arm__)
        framePointer = ctx->r[11];
        stackPointer = ctx->sp;
        instructionPointer = ctx->pc;
#endif

        StackFrame currentFrame;
        currentFrame.address = instructionPointer;
        resolveSymbol(currentFrame);
        frames.push_back(currentFrame);

        size_t frameCount = 1;
        uintptr_t currentFP = framePointer;

        while (frameCount < maxFrames && currentFP != 0 && isValidAddress(currentFP))
        {
            uintptr_t nextFP, returnAddr;

#if defined(__x86_64__) || defined(__i386__)
            if (!safeRead(currentFP, nextFP) || !safeRead(currentFP + sizeof(uintptr_t), returnAddr))
                break;
#elif defined(__aarch64__)
            if (!safeRead(currentFP, nextFP) || !safeRead(currentFP + 8, returnAddr))
                break;
#elif defined(__arm__)
            if (!safeRead(currentFP, nextFP) || !safeRead(currentFP + 4, returnAddr))
                break;
#endif

            if (returnAddr == 0 || !isValidAddress(returnAddr))
                break;

            StackFrame frame;
            frame.address = returnAddr;
            resolveSymbol(frame);
            frames.push_back(frame);

            currentFP = nextFP;
            frameCount++;

            if (nextFP <= currentFP)
                break;
        }

        return frames;
    }
};

#endif // _REPP_H