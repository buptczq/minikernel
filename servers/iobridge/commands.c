#include "commands.h"
#include <resea/cmdline.h>
#include <resea/ipc.h>
#include <resea/malloc.h>
#include <resea/printf.h>
#include <resea/syscall.h>
#include <string.h>

static void ps_command(__unused int argc, __unused char **argv) {
    kdebug("ps");
}

static void quit_command(__unused int argc, __unused char **argv) {
    kdebug("q");
}

static void *hex_str_to_ptr(char *hex_str) {
  unsigned long hex_num = 0;
  char *p = hex_str;
  if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
    p += 2;
  }
  while (*p) {
    char c = *p;
    int n = 0;
    if (c >= '0' && c <= '9') {
      n = c - '0';
    }
    else if (c >= 'A' && c <= 'F') {
      n = c - 'A' + 10;
    }
    else if (c >= 'a' && c <= 'f') {
      n = c - 'a' + 10;
    }
    else {
      break;
    }
    hex_num = (hex_num << 4) + n;
    p++;
  }
  return (void *)hex_num;
}

#ifdef CONFIG_ARCH_X64
static void io_read8_command(int argc, char **argv) {
    if (argc < 2) {
        WARN("io.read8: too few arguments");
        return;
    }

    uint8_t value = 0;
    uint16_t port = (uint16_t)hex_str_to_ptr(argv[1]);
    __asm__ __volatile__("inb %1, %0" : "=a"(value) : "Nd"(port));
    printf("port %p value %p\n", (void*)port, (void*)value);
}

static void io_read16_command(int argc, char **argv) {
    if (argc < 2) {
        WARN("io.read16: too few arguments");
        return;
    }

    uint16_t value = 0;
    uint16_t port = (uint16_t)hex_str_to_ptr(argv[1]);
    __asm__ __volatile__("inw %1, %0" : "=a"(value) : "Nd"(port));
    printf("port %p value %p\n", (void*)port, (void*)value);
}

static void io_read32_command(int argc, char **argv) {
    if (argc < 2) {
        WARN("io.read32: too few arguments");
        return;
    }

    uint32_t value = 0;
    uint16_t port = (uint16_t)hex_str_to_ptr(argv[1]);
    __asm__ __volatile__("inl %1, %0" : "=a"(value) : "Nd"(port));
    printf("port %p value %p\n", (void*)port, (void*)value);
}

static void io_write8_command(int argc, char **argv) {
    if (argc < 3) {
        WARN("io.write8: too few arguments");
        return;
    }

    uint16_t port = (uint16_t)hex_str_to_ptr(argv[1]);
    uint8_t value = (uint8_t)hex_str_to_ptr(argv[2]);
    __asm__ __volatile__("outb %0, %1" ::"a"(value), "Nd"(port));
    printf("port %p value %p\n", (void*)port, (void*)value);
}

static void io_write16_command(int argc, char **argv) {
    if (argc < 3) {
        WARN("io.write16: too few arguments");
        return;
    }

    uint16_t port = (uint16_t)hex_str_to_ptr(argv[1]);
    uint16_t value = (uint16_t)hex_str_to_ptr(argv[2]);
    __asm__ __volatile__("outw %0, %1" ::"a"(value), "Nd"(port));
    printf("port %p value %p\n", (void*)port, (void*)value);
}

static void io_write32_command(int argc, char **argv) {
    if (argc < 3) {
        WARN("io.write32: too few arguments");
        return;
    }

    uint16_t port = (uint16_t)hex_str_to_ptr(argv[1]);
    uint32_t value = (uint32_t)hex_str_to_ptr(argv[2]);
    __asm__ __volatile__("outl %0, %1" ::"a"(value), "Nd"(port));
    printf("port %p value %p\n", (void*)port, (void*)value);
}
#endif

static void mmap_command(int argc, char **argv) {
    if (argc < 3) {
        WARN("mmap: too few arguments");
        return;
    }

    uint64_t paddr = (uint64_t)hex_str_to_ptr(argv[1]);
    int page = (int)hex_str_to_ptr(argv[2]);

    struct message m;
    m.type = VM_ALLOC_PAGES_MSG;
    m.vm_alloc_pages.paddr = (paddr_t)paddr;
    m.vm_alloc_pages.num_pages = (size_t)page;
    error_t err = ipc_call(VM_TASK, &m);
    ASSERT_OK(err);
    ASSERT(m.type == VM_ALLOC_PAGES_REPLY_MSG);

    printf("paddr %p vaddr %p page %d\n", m.vm_alloc_pages_reply.paddr,
            m.vm_alloc_pages_reply.vaddr, page);

}

#define MEM_READ_TPL(BITS) \
    static void mem_read##BITS##_command(int argc, char **argv) { \
        if (argc < 2) { \
            WARN("mem.read" #BITS ": too few arguments");\
            return;\
        }\
        __sync_synchronize(); \
        uint##BITS##_t* addr = (uint##BITS##_t*)hex_str_to_ptr(argv[1]);\
        printf("addr %p value %p\n", (void*)addr, (void*)(*addr));\
    }

MEM_READ_TPL(8)
MEM_READ_TPL(16)
MEM_READ_TPL(32)
MEM_READ_TPL(64)

#define MEM_WRITE_TPL(BITS) \
    static void mem_write##BITS##_command(int argc, char **argv) { \
        if (argc < 2) { \
            WARN("mem.write" #BITS ": too few arguments");\
            return;\
        }\
        uint##BITS##_t* addr = (uint##BITS##_t*)hex_str_to_ptr(argv[1]);\
        uint##BITS##_t value = (uint##BITS##_t)hex_str_to_ptr(argv[2]);\
        *addr = value; \
        __sync_synchronize(); \
        printf("addr %p value %p\n", (void*)addr, (void*)(value));\
    }
MEM_WRITE_TPL(8)
MEM_WRITE_TPL(16)
MEM_WRITE_TPL(32)
MEM_WRITE_TPL(64)

static void help_command(__unused int argc, __unused char **argv) {
    INFO("help                    -  Print this message.");
    INFO("<task> cmdline...       -  Launch a task.");
    INFO("ps                      -  List tasks.");
    INFO("q                       -  Halt the computer.");
#ifdef CONFIG_ARCH_X64
    INFO("io.read8 port           -  Read uint8 from port.");
    INFO("io.read16 port          -  Read uint16 from port.");
    INFO("io.read32 port          -  Read uint32 from port.");
    INFO("io.write8 port value    -  Write uint8 to port.");
    INFO("io.write16 port value   -  Write uint16 to port.");
    INFO("io.write32 port value   -  Write uint32 to port.");
#endif
    INFO("mmap paddr page_num     -  mmap physical page.");
    INFO("mem.read8 addr          -  Read uint8 from addr.");
    INFO("mem.read16 addr         -  Read uint16 from addr.");
    INFO("mem.read32 addr         -  Read uint32 from addr.");
    INFO("mem.read64 addr         -  Read uint64 from addr.");
    INFO("mem.write8 addr         -  Write uint8 to addr.");
    INFO("mem.write16 addr        -  Write uint16 to addr.");
    INFO("mem.write32 addr        -  Write uint32 to addr.");
    INFO("mem.write64 addr        -  Write uint64 to addr.");
}

struct command commands[] = {
    {.name = "help", .run = help_command},
    {.name = "ps", .run = ps_command},
    {.name = "q", .run = quit_command},
#ifdef CONFIG_ARCH_X64
    {.name = "io.read8", .run = io_read8_command},
    {.name = "io.read16", .run = io_read16_command},
    {.name = "io.read32", .run = io_read32_command},
    {.name = "io.write8", .run = io_write8_command},
    {.name = "io.write16", .run = io_write16_command},
    {.name = "io.write32", .run = io_write32_command},
#endif
    {.name = "mmap", .run = mmap_command},
    {.name = "mem.read8", .run = mem_read8_command},
    {.name = "mem.read16", .run = mem_read16_command},
    {.name = "mem.read32", .run = mem_read32_command},
    {.name = "mem.read64", .run = mem_read64_command},
    {.name = "mem.write8", .run = mem_write8_command},
    {.name = "mem.write16", .run = mem_write16_command},
    {.name = "mem.write32", .run = mem_write32_command},
    {.name = "mem.write64", .run = mem_write64_command},
    {.name = NULL, .run = NULL},
};

