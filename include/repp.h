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

    struct HookContext
    {
        char *targetAddress;
        char *replacementFunction;
        char *trampoline;
        uint8_t originalBytes[32];
        size_t patchSize;
        bool isHooked;
    };

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
};

#endif // _REPP_H