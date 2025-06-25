#ifndef REPPH
#define REPPH

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

    struct HookContext
    {
        char *targetAddress;
        char *replacementFunction;
        char *trampoline;
        uint8_t originalBytes[32];
        size_t patchSize;
        bool isHooked;
    };

    struct InterceptContext
    {
        std::function<void(uintptr_t *)> onEnter;
        std::function<void(uintptr_t *)> onLeave;
        uintptr_t originalAddr;
        uintptr_t trampolineAddr;
        uint32_t originalBytes[4];
        bool active;
        bool isThumb;
    };

    static std::map<uintptr_t, InterceptContext *> interceptors;

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

    static bool protectMemory(uintptr_t address, size_t size, int protection)
    {
        size_t pageSize = static_cast<size_t>(getpagesize());
        uintptr_t start = address & ~(pageSize - 1);
        uintptr_t end = (address + size - 1) & ~(pageSize - 1);
        size_t totalSize = (end - start) + pageSize;
        return mprotect(reinterpret_cast<void *>(start), totalSize, protection) == 0;
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
        char *result = nullptr;
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

    static uintptr_t createTrampoline(InterceptContext *ctx)
    {
        size_t trampolineSize = 64;
        void *trampoline = mmap(nullptr, trampolineSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (trampoline == MAP_FAILED)
            return 0;
        uint32_t *code = (uint32_t *)trampoline;
        int idx = 0;
        if (ctx->isThumb)
        {
            uint16_t *thumbCode = (uint16_t *)trampoline;
            int thumbIdx = 0;
            thumbCode[thumbIdx++] = 0xB5FF;
            thumbCode[thumbIdx++] = 0x4668;
            if (ctx->onEnter)
            {
                thumbCode[thumbIdx++] = 0x4A05;
                thumbCode[thumbIdx++] = 0x4790;
            }
            thumbCode[thumbIdx++] = 0xBDFF;
            if (thumbIdx & 1)
                thumbIdx++;
            if (ctx->onEnter)
            {
                auto target = ctx->onEnter.target<void (*)(void *)>();
                if (target)
                {
                    *reinterpret_cast<uintptr_t *>(&thumbCode[thumbIdx]) = (uintptr_t)target;
                    thumbIdx += 2;
                }
            }
        }
        else
        {
            code[idx++] = 0xE92D4FFF;
            code[idx++] = 0xE1A0000D;
            if (ctx->onEnter)
            {
                code[idx++] = 0xE59FC008;
                code[idx++] = 0xE12FFF3C;
            }
            code[idx++] = 0xE8BD4FFF;
            code[idx++] = 0xE59FC000;
            code[idx++] = 0xE12FFF1C;
            if (ctx->onEnter)
            {
                auto target = ctx->onEnter.target<void (*)(void *)>();
                if (target)
                {
                    code[idx++] = (uintptr_t)target;
                }
            }
            code[idx++] = ctx->originalAddr;
        }
        __builtin___clear_cache((char *)trampoline, (char *)trampoline + trampolineSize);
        return (uintptr_t)trampoline;
    }

    static void hookTrampoline(void *regs)
    {
        uintptr_t *sp = (uintptr_t *)regs;
        uintptr_t pc = sp[13];
        auto it = interceptors.find(pc);
        if (it != interceptors.end() && it->second->active && it->second->onEnter)
        {
            it->second->onEnter((uintptr_t *)regs);
        }
    }

    static InterceptContext *interceptFunction(uintptr_t address,
                                               std::function<void(uintptr_t *)> onEnter = nullptr,
                                               std::function<void(uintptr_t *)> onLeave = nullptr)
    {
        bool isThumb = (address & 1) != 0;
        uintptr_t realAddr = address & ~1;
        InterceptContext *ctx = new InterceptContext();
        ctx->onEnter = onEnter;
        ctx->onLeave = onLeave;
        ctx->originalAddr = realAddr;
        ctx->active = true;
        ctx->isThumb = isThumb;
        if (mprotect((void *)(realAddr & ~0xFFF), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        {
            delete ctx;
            return nullptr;
        }
        memcpy(ctx->originalBytes, (void *)realAddr, 16);
        ctx->trampolineAddr = createTrampoline(ctx);
        if (!ctx->trampolineAddr)
        {
            delete ctx;
            return nullptr;
        }
        interceptors[realAddr] = ctx;
        if (isThumb)
        {
            uint16_t *target = (uint16_t *)realAddr;
            int32_t offset = (ctx->trampolineAddr - realAddr - 4) / 2;
            if (offset >= -2048 && offset <= 2047)
            {
                target[0] = 0xE000 | (offset & 0x7FF);
            }
            else
            {
                target[0] = 0x4778;
                target[1] = 0x46C0;
                *reinterpret_cast<uint32_t *>(&target[2]) = ctx->trampolineAddr | 1;
            }
        }
        else
        {
            uint32_t *target = (uint32_t *)realAddr;
            int32_t offset = (ctx->trampolineAddr - realAddr - 8) / 4;
            if (offset >= -0x800000 && offset <= 0x7FFFFF)
            {
                target[0] = 0xEA000000 | (offset & 0x00FFFFFF);
            }
            else
            {
                target[0] = 0xE51FF004;
                target[1] = ctx->trampolineAddr;
            }
        }
        __builtin___clear_cache((char *)realAddr, (char *)(realAddr + 16));
        return ctx;
    }

    static bool detachIntercept(uintptr_t address)
    {
        uintptr_t realAddr = address & ~1;
        auto it = interceptors.find(realAddr);
        if (it == interceptors.end())
            return false;
        InterceptContext *ctx = it->second;
        if (mprotect((void *)(realAddr & ~0xFFF), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        {
            return false;
        }
        memcpy((void *)realAddr, ctx->originalBytes, 16);
        __builtin___clear_cache((char *)realAddr, (char *)(realAddr + 16));
        if (ctx->trampolineAddr)
        {
            munmap((void *)ctx->trampolineAddr, 64);
        }
        delete ctx;
        interceptors.erase(it);
        return true;
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

    static uintptr_t findSymbol(const std::string &moduleName, const std::string &symbolName)
    {
        char *addr = getExportByName(moduleName.c_str(), symbolName.c_str());
        return reinterpret_cast<uintptr_t>(addr);
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

    static Module *findModule(const std::string &name)
    {
        static std::vector<Module> modules = enumerateModules();
        for (auto &module : modules)
        {
            if (module.name == name)
            {
                return &module;
            }
        }
        return nullptr;
    }

    static uintptr_t dlsymAddress(const std::string &library, const std::string &symbol)
    {
        void *handle = dlopen(library.c_str(), RTLD_NOW);
        if (!handle)
            return 0;
        void *addr = dlsym(handle, symbol.c_str());
        dlclose(handle);
        return reinterpret_cast<uintptr_t>(addr);
    }

    static bool patchCode(uintptr_t address, const uint8_t *code, size_t size)
    {
        if (!protectMemory(address, size, PROT_READ | PROT_WRITE | PROT_EXEC))
            return false;
        memcpy(reinterpret_cast<void *>(address), code, size);
        clearCache(reinterpret_cast<char *>(address), size);
        return true;
    }

    static bool nopInstruction(uintptr_t address)
    {
#if defined(__arm__)
        uint8_t nop[] = {0x00, 0xF0, 0x20, 0xE3};
        return patchCode(address, nop, 4);
#elif defined(__aarch64__)
        uint32_t nop = 0xD503201F;
        return writeMemory<uint32_t>(address, nop);
#elif defined(__i386__) || defined(__x86_64__)
        uint8_t nop = 0x90;
        return writeMemory<uint8_t>(address, nop);
#endif
        return false;
    }

    static bool retInstruction(uintptr_t address)
    {
#if defined(__arm__)
        uint8_t ret[] = {0x1E, 0xFF, 0x2F, 0xE1};
        return patchCode(address, ret, 4);
#elif defined(__aarch64__)
        uint32_t ret = 0xD65F03C0;
        return writeMemory<uint32_t>(address, ret);
#elif defined(__i386__) || defined(__x86_64__)
        uint8_t ret = 0xC3;
        return writeMemory<uint8_t>(address, ret);
#endif
        return false;
    }

    static bool jumpTo(uintptr_t from, uintptr_t to)
    {
#if defined(__arm__)
        int32_t offset = (to - from - 8) / 4;
        if (offset >= -0x800000 && offset <= 0x7FFFFF)
        {
            uint32_t instruction = 0xEA000000 | (offset & 0x00FFFFFF);
            return writeMemory<uint32_t>(from, instruction);
        }
        else
        {
            uint8_t jump[] = {0x04, 0xF0, 0x1F, 0xE5};
            if (!patchCode(from, jump, 4))
                return false;
            return writeMemory<uint32_t>(from + 4, to);
        }
#elif defined(__aarch64__)
        int64_t offset = to - from;
        if (offset >= -0x8000000 && offset <= 0x7FFFFFF && (offset & 3) == 0)
        {
            uint32_t instruction = 0x14000000 | ((offset >> 2) & 0x03FFFFFF);
            return writeMemory<uint32_t>(from, instruction);
        }
#elif defined(__i386__)
        int32_t offset = to - from - 5;
        uint8_t jump[] = {0xE9, 0x00, 0x00, 0x00, 0x00};
        *reinterpret_cast<int32_t *>(jump + 1) = offset;
        return patchCode(from, jump, 5);
#elif defined(__x86_64__)
        uint8_t jump[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        *reinterpret_cast<uint64_t *>(jump + 6) = to;
        return patchCode(from, jump, 14);
#endif
        return false;
    }

    static Module *findModule(const std::string &name)
    {
        static std::vector<Module> modules = enumerateModules();
        for (auto &module : modules)
        {
            if (module.name == name)
            {
                return &module;
            }
        }
        return nullptr;
    }

    static uintptr_t dlsymAddress(const std::string &library, const std::string &symbol)
    {
        void *handle = dlopen(library.c_str(), RTLD_NOW);
        if (!handle)
            return 0;

        void *addr = dlsym(handle, symbol.c_str());
        dlclose(handle);
        return reinterpret_cast<uintptr_t>(addr);
    }

    inline void replace(uintptr_t ptr, const std::vector<uint8_t> &arr)
    {
        protectMemory(ptr, arr.size(), PROT_READ | PROT_WRITE | PROT_EXEC);
        writeBytes(ptr, arr.data(), arr.size());
        protectMemory(ptr, arr.size(), PROT_READ | PROT_EXEC);
    }
};
#endif