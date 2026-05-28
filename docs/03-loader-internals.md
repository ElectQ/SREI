# Loader 内部机制

本文深入分析 SREI 运行时 Loader 的内部实现。Loader 是整个注入框架的核心组件,负责在目标进程中完成 ELF 共享库的内存布局重建、重定位修复和初始化调用。与 sRDI (Shellcode Reflective DLL Injection) 在 Windows 平台上的实现类似,SREI 的 Loader 必须在无 libc 支持、无动态链接器协助的条件下,独立完成一个完整 ELF 加载器的全部工作。

## PE-ELF 加载器对照表

下表对比了 Windows sRDI 与 Linux SREI 在各加载阶段的技术实现差异:

| sRDI (Windows) | SREI (Linux) | 说明 |
|---|---|---|
| PEB → LDR_MODULE | link_map / /proc/self/maps | 已加载模块发现 |
| GetProcAddress (按名字) | GNU hash / SysV hash (按名字) | 符号查找 |
| IMAGE_BASE_RELOCATION processing | REBASE fixup (*slot += slide) | 基址重定位 |
| IAT patching | IMPORT fixup (resolve + write GOT) | 导入地址修复 |
| DllMain 调用 | init_array 按序调用 | 初始化函数 |
| 无等价机制 | IRELATIVE fixup (IFUNC resolver) | 间接函数 |
| 无等价机制 | TLS fixup + 自定义 __tls_get_addr | 线程本地存储 |

Windows PE 格式的加载流程相对统一——PEB 遍历模块链表、`GetProcAddress` 按序号或名称查找、`IMAGE_BASE_RELOCATION` 批量重定位、IAT 集中修复、最后调用 `DllMain`。Linux ELF 格式则更为复杂:模块发现需要通过 `link_map` 链表或解析 `/proc/self/maps`;符号查找需要实现 GNU hash 和 SysV hash 两套算法;重定位类型包括 `R_X86_64_RELATIVE`(基址重定位)、`R_X86_64_GLOB_DAT`/`R_X86_64_JUMP_SLOT`(导入修复)、`R_X86_64_IRELATIVE`(IFUNC 间接函数)以及 `R_X86_64_TPOFF64`(TLS 变量偏移)等多种类型。此外,SREI 还需要处理 `init_array` 初始化函数数组的按序调用,以及 TLS 模板的内存分配和 `__tls_get_addr` 的自定义实现——这些在 Windows sRDI 中都没有等价机制。

## PIC(位置无关代码)约束

Loader 以 shellcode 形式嵌入到载荷中,执行地址完全不可预知。这带来了三个核心约束。

### 约束一:不能使用全局变量(常规方式)

位置无关代码没有固定的 GOT 地址,因此无法通过常规方式访问全局变量。Loader 的所有状态通过函数参数和栈变量传递。然而,TLS 管理功能需要持久的静态变量(如线程局部存储块指针、dtv 缓存等),这些变量必须在函数调用间保持有效。

解决方案是通过链接脚本 `linker.ld` 将 `.data` 和 `.bss` 段合并到同一个可写 section 中,然后使用 `objcopy` 的 `-j .data -j .bss` 选项将其一并提取。这些静态变量通过 GOT 中的 `R_X86_64_RELATIVE` 重定位获得正确的地址,而这类重定位由 bootstrap 阶段自动处理。本质上,Loader 自身也经历了一次微型"加载"过程:bootstrap 代码遍历 Loader 的重定位表,修复其内部的 GOT 条目,使静态变量在运行时指向正确的内存位置。

### 约束二:不能使用标准库

Loader 运行在目标进程的地址空间中,不能依赖任何 libc 函数。所有的内存操作、文件 I/O 和系统交互都通过内联汇编直接发起系统调用实现。`syscall.h` 头文件封装了 Loader 用到的 9 个系统调用,对应的 x86_64 系统调用号自 Linux 内核 2.6 以来从未改变,这保证了跨内核版本的兼容性。从用户态角度来看,这些系统调用号属于稳定的内核 ABI,不会因 glibc 版本更新而失效。

### 约束三:不能使用字符串常量的常规寻址

GCC 在 `-fPIC` 模式下编译字符串引用时,会自动生成 RIP 相对寻址指令(如 `lea rax, [rip+offset]`),这天然就是位置无关的。链接脚本将 `.text.entry` 放在最前面(确保 `_srei_loader` 入口函数位于 Loader shellcode 的起始位置),其后依次是 `.text`、`.rodata`。最终通过 `objcopy` 提取 `.text`、`.rodata`、`.data`、`.bss` 的原始字节作为 Loader shellcode。由于 RIP 相对寻址只依赖指令与数据的相对偏移,而链接脚本保证了这些段在输出中的连续性,因此字符串常量的访问在任何加载地址下都能正确工作。

## 系统调用封装

Loader 通过 9 个系统调用完成全部与内核的交互。每个封装函数使用相同的代码模式:内联 `asm volatile` 指令,`syscall` 指令触发系统调用,寄存器约束遵循 SysV AMD64 ABI 规范——参数依次通过 `rdi`、`rsi`、`rdx`、`r10`、`r8`、`r9` 传递(注意第 4 个参数使用 `r10` 而非 `rcx`,因为 `syscall` 指令本身会破坏 `rcx`),clobber 列表包含 `"rcx"`、`"r11"`、`"memory"`。

### sys_mmap (系统调用号 9)

```c
static inline void *sys_mmap(void *addr, size_t len, int prot,
                              int flags, int fd, off_t off)
{
    void *ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(9), "D"(addr), "S"(len), "d"(prot),
          "r"((uint64_t)flags), "r"((uint64_t)fd), "r"((uint64_t)off)
        : "rcx", "r11", "memory"
    );
    return ret;
}
```

`sys_mmap` 是 Loader 中最关键的系统调用,用于为 ELF 映像分配内存。它是 Loader 中唯一需要 6 个参数的系统调用,因此需要用到 `r8` 和 `r9` 寄存器。在内联汇编中,第 5、6 个参数通过 `"r"` 约束传入,编译器会自动选择合适的寄存器(通常是 `r8`、`r9` 或其他可用寄存器),由于 SysV ABI 要求 `syscall` 指令的参数通过 `r10`(非 `rcx`)传递第 4 个参数,这里通过约束确保正确映射。

### sys_mprotect (系统调用号 10)

```c
static inline int sys_mprotect(void *addr, size_t len, int prot)
```

用于设置内存段的权限属性(读/写/执行)。在 ELF 加载过程中,Loader 先以 `PROT_READ | PROT_WRITE` 映射所有段,完成重定位修复后再根据 ELF `p_flags` 设置最终权限。对于启用了 RELRO (Read-Only After Relocation) 的段,`sys_mprotect` 在重定位完成后将 `.got` 等区域设置为只读,增强安全性。

**页对齐处理：** Linux 的 `mprotect` 系统调用要求 `addr` 参数必须是页对齐的（4096 字节对齐），否则返回 `EINVAL`。然而 llbin 段表中记录的偏移直接来自 ELF 的 PT_LOAD vaddr，不保证页对齐——例如 Rust cdylib 的代码段起始偏移为 `0x15d0`。因此在调用 `sys_mprotect` 之前，Loader 需要对每个段执行页对齐处理：将起始地址向下对齐到 `addr & ~0xfff`，将结束地址向上扩展到 `(end + 0xfff) & ~0xfff`。这一处理确保所有 ELF 文件（包括 Rust、C、C++ 编译产生的各种段布局）都能被正确设置权限。

### sys_munmap (系统调用号 11)

```c
static inline int sys_munmap(void *addr, size_t len)
```

在加载失败时用于释放已分配的内存。Loader 在每个可能失败的步骤(内存分配、ELF 解析、重定位等)之后都设置了错误处理路径,通过 `sys_munmap` 清理已映射的内存区域,避免在目标进程中留下无用的内存映射。

### sys_open (系统调用号 2)

```c
static inline int sys_open(const char *path, int flags, int mode)
```

用于打开 `/proc/self/auxv` 和 `/proc/self/maps`。在自解析模式下,Loader 需要读取这两个伪文件来发现已加载的共享库。`/proc/self/auxv` 提供辅助向量(auxiliary vector),其中包含动态链接器的基地址(AT_BASE 条目);`/proc/self/maps` 列出当前进程的全部内存映射,作为 `link_map` 不可用时的回退方案。

### sys_read (系统调用号 0)

```c
static inline ssize_t sys_read(int fd, void *buf, size_t count)
```

用于读取文件描述符的内容。Loader 将 `/proc/self/auxv` 的数据(约 320 字节)和 `/proc/self/maps` 的数据(最多 8KB)读入栈缓冲区,避免额外的内存分配。栈缓冲区是 PIC 环境下最安全的数据存储方式——它不依赖任何固定地址,且生命周期由函数调用栈管理。

### sys_close (系统调用号 3)

```c
static inline int sys_close(int fd)
```

关闭已打开的文件描述符。在读取 `/proc/self/auxv` 或 `/proc/self/maps` 完成后立即关闭,防止文件描述符泄漏。

### sys_write (系统调用号 1)

```c
static inline ssize_t sys_write(int fd, const void *buf, size_t count)
```

用于可选的调试输出。在正常的生产构建中不会使用,仅在调试构建中用于向 stderr 输出诊断信息。

### sys_exit (系统调用号 60)

```c
static inline void sys_exit(int code)
```

在遇到致命错误时终止 Loader 执行。由于 Loader 运行在 shellcode 上下文中,没有常规的错误传播机制,`sys_exit` 是唯一可靠的异常终止方式。它会立即终止目标进程,避免在不确定状态下继续执行。

### sys_arch_prctl (系统调用号 158)

```c
static inline int sys_arch_prctl(int code, unsigned long *addr)
```

用于获取 TLS 基地址。通过 `ARCH_GET_FS` 代码读取 `%fs` 段寄存器的值,该值指向当前线程的 TLS 控制块(tcbhead)。这是 SREI 实现 TLS 支持的基础——Loader 需要知道现有 TLS 区域的布局,才能正确分配新的 TLS 存储并安装自定义的 `__tls_get_addr` 函数。

## 链接脚本设计 (linker.ld)

链接脚本精确控制 Loader 各段在输出文件中的排列顺序和包含内容:

```ld
SECTIONS {
    . = 0;
    .text : { *(.text.entry) *(.text) *(.text.*) }
    .rodata : { *(.rodata) *(.rodata.*) }
    .data : { *(.data) *(.data.*) *(.bss) *(.bss.*) *(COMMON) }
    /DISCARD/ : { *(.comment) *(.note.*) *(.eh_frame*) *(.gnu.hash) *(.dynsym) *(.dynstr) *(.dynamic) *(.got) *(.got.plt) *(.plt) }
}
```

关键设计决策及其理由:

**`. = 0` 基址归零**: 所有符号地址和段偏移从 0 开始计算。这意味着 Loader 内部的所有地址引用都是相对偏移,不包含绝对地址。结合 RIP 相对寻址,Loader 可以在任意地址正确执行。

**`.text.entry` 置于最前**: 将 `_srei_loader` 入口函数所在的 `.text.entry` 段放在 `.text` 段的第一位,确保该函数的机器码位于 Loader shellcode 的最起始位置。shellcode 调用者(bootstrap 代码)通过相对跳转到达入口,起始位置的确定性保证了偏移量计算的可靠性。

**`.data` 合并 `.bss`**: 将 `.bss` 段并入 `.data` 段,使静态可变变量(初始值为零的变量)与已初始化变量连续存放。由于 `objcopy -O binary` 不生成段头信息,合并后的 `.data` 段作为一个整体被提取,`.bss` 变量无需单独的段来声明其存在。这些变量在 shellcode 中占据实际的零字节空间,bootstrap 加载时会正确处理。

**DISCARD 段**: 移除所有动态链接产物。Loader 是一个独立运行的(freestanding)程序,不依赖动态链接器,因此 `.gnu.hash`、`.dynsym`、`.dynstr`、`.dynamic`、`.got`、`.got.plt`、`.plt` 等段都是多余的。`.eh_frame` 帧信息也被丢弃(Loader 不使用异常处理)。`.comment` 和 `.note.*` 是编译器元数据,同样不需要。最终通过 `objcopy -O binary -j .text -j .rodata -j .data -j .bss` 提取纯净的机器码字节。

## 编译优化 (-Os vs -O2)

Loader 使用 `-Os`(优化代码大小)而非 `-O2`(优化执行速度)进行编译。这一选择基于实际的代码体积对比:

- `-O2` 编译:Loader 约 5140 字节。`-O2` 的激进内联策略会将所有 `static inline` 函数(包括 9 个系统调用封装、哈希函数、ELF 解析辅助函数等)在每个调用点展开,导致代码膨胀。
- `-Os` 编译:编译器会做出更合理的内联决策,仅在确实有利于减小编码体积时才内联函数调用。

启用 TLS 支持和 eh_frame 后,最终 Loader 大小为 5560 字节（含 mprotect 页对齐逻辑）。对于 shellcode 场景,每一个字节都很重要——shellcode 通常通过网络传输或在受限环境中执行,更小的体积意味着更低的检测率和更高的可靠性。`-Os` 的代价是某些非关键路径的执行速度略慢,但对于一次性执行的 Loader 来说,这个代价完全可以接受。

## Word-aligned memcpy

Loader 在将 ELF 映像从 llbin 缓冲区复制到 mmap 分配的目标内存时,使用了 8 字节对齐的字(word)拷贝,而非逐字节拷贝:

```c
static inline void *srei_memcpy(void *dst, const void *src, size_t n)
{
    uint64_t *d8 = (uint64_t *)((uintptr_t)dst & ~7);
    const uint64_t *s8 = (const uint64_t *)((uintptr_t)src & ~7);
    size_t words = n >> 3;
    size_t tail = n & 7;

    for (size_t i = 0; i < words; i++)
        d8[i] = s8[i];

    uint8_t *d1 = (uint8_t *)(d8 + words);
    const uint8_t *s1 = (const uint8_t *)(s8 + words);
    for (size_t i = 0; i < tail; i++)
        d1[i] = s1[i];

    return dst;
}
```

对于典型的 .so 映像(10-100KB 范围),8 字节 word 拷贝相比逐字节拷贝约有 8 倍的速度提升。这个优化仅增加了约 31 字节的代码,是极具性价比的权衡。尾部不足 8 字节的部分通过逐字节拷贝处理,确保正确性。

## Bootstrap:参数传递的桥梁

Shellcode 调用者(如 exploit payload)只能跳转到 Loader 的起始地址执行,无法传递参数。Bootstrap 代码(68 字节)作为桥梁,解决了参数传递问题:

1. **获取当前执行地址**: 使用经典的 shellcode PIC 技巧——`call $+5 / pop rax`。`call $+5` 将下一条指令的地址压入栈中,`pop rax` 将其弹出到 `rax`。由于 `call $+5` 的编码为 `E8 00 00 00 00`(5 字节),`pop rax` 执行后 `rax` 的值恰好是 `pop` 指令本身的地址。这样 Loader 就获得了自身在内存中的实际地址。

2. **计算 llbin 数据指针**: `lea rdi, [rax + llbin_offset]`。`llbin_offset` 是在汇编时确定的常量,表示 llbin 数据相对于 `pop` 指令的偏移量。由于 llbin 数据紧接在 Loader shellcode 之后,这个偏移量等于 Loader shellcode 的大小加上 bootstrap 代码中的指令长度。

3. **设置 SysV AMD64 寄存器参数**: 按照 SysV AMD64 调用约定,将 6 个参数设置到对应寄存器:
   - `rdi` = llbin 数据指针(待加载的 .so 文件的原始字节)
   - `rsi` = llbin 数据长度
   - `rdx` = 导出函数哈希(ROTR13 哈希值,用于在加载完成后查找指定函数)
   - `rcx` = user_data 指针(传递给导出函数的用户数据)
   - `r8` = user_data 长度
   - `r9` = dlsym_fn 函数指针(设为 NULL 表示使用自解析模式)
   - `[rsp]` = flags(SREI_CLEARHEADER 清除 ELF 头部 | SREI_CLEARMEMORY 清除 Loader 自身)

4. **16 字节栈对齐**: x86_64 ABI 要求在执行 `call` 指令前栈必须 16 字节对齐。Bootstrap 通过 `push rbp`、`mov rbp, rsp`、`and rsp, -16` 三个指令确保栈对齐。`push rbp` 还保存了调用者的栈帧指针,便于后续恢复。

5. **相对调用入口函数**: 通过相对 `call` 指令跳转到 `srei_load` 入口函数。由于 `srei_load` 位于 `.text.entry` 段的最开头,而 `.text.entry` 又是 `.text` 段的第一个输入段,其偏移量在链接时即可确定。

Bootstrap 代码中所有指令的编码长度都是预先确定的(手动选择的指令编码),因此 `llbin_offset` 等偏移量在汇编时即可计算,不需要运行时重定位。

## 自解析模式:link_map 快路径

自解析模式(Self-resolve mode)是 SREI Loader 最独特的功能:在不需要 `dlsym` 外部函数的情况下,独立完成符号解析。这一功能通过双路径策略实现。

### link_map 快路径(glibc / Android Bionic)

快路径利用了 SVR4 调试器协议中定义的 `link_map` 结构,该结构是 glibc、musl、Bionic 共同遵守的 ABI:

1. **读取辅助向量**: 打开 `/proc/self/auxv`(约 320 字节,使用栈缓冲区),遍历查找 `AT_BASE` 条目。`AT_BASE` 保存了动态链接器(ld.so)的基地址。

2. **定位 _r_debug**: 以动态链接器的基地址为起点,解析其 ELF 头部,找到符号表。在 glibc 中,`_r_debug` 自 2.0 版本以来就被导出,且其 ABI 从未改变。通过在动态链接器的符号表中搜索 `_r_debug`,获取其地址。

3. **遍历 link_map 链表**: `_r_debug` 结构体的 `r_map` 字段(偏移 +8)指向 `link_map` 链表的头节点。遍历链表即可获取进程中所有已加载共享库的信息。

`link_map` 的前 5 个字段属于 SVR4 调试器协议 ABI,在 glibc、musl、Bionic 之间保持一致:

```c
struct link_map {
    uintptr_t l_addr;       // +0  load bias(加载偏移)
    char      *l_name;      // +8  路径名
    Elf64_Dyn *l_ld;        // +16 直接指向 .dynamic 段
    link_map  *l_next;      +24 下一个节点
    link_map  *l_prev;      // +32 上一个节点
};
```

关键优势在于 `l_ld` 直接提供了 `.dynamic` 段的指针。常规 ELF 加载流程需要:解析 ELF 头部 → 遍历程序头表找到 `PT_DYNAMIC` → 计算虚拟地址到文件偏移的映射 → 最终定位 `.dynamic` 段。通过 `link_map.l_ld`,这一流程被简化为一次指针解引用。同样,`l_addr` 直接提供了 `load_bias`,无需从 ELF 头部和程序头中推算。

对于 Android/Bionic 环境,Loader 还会额外从 `linker64` 中解析 `dlopen` 函数,因为 Bionic 的动态链接器与 glibc 有不同的符号导出策略。

## 自解析模式:/proc/self/maps 回退路径

当 `link_map` 快路径失败时(典型场景:musl 的 `ld-musl` 不导出 `_r_debug` 符号),Loader 切换到回退路径:

1. **读取 /proc/self/maps**: 使用 8KB 的栈缓冲区读取完整的内存映射信息(不使用 `mmap`,避免引入额外的内存分配)。8KB 足以容纳典型进程的全部映射条目。

2. **逐行解析**: 每行格式为 `start-end perms offset dev inode pathname`。Loader 提取每行的基地址(start)和路径名(pathname),筛选出 `.so` 文件的映射。

3. **去重处理**: 同一个 `.so` 会被映射到多个地址范围(代码段、数据段、只读段等),Loader 通过比较路径名进行去重,确保每个 `.so` 只被解析一次。

4. **完整 ELF 解析**: 对每个 `.so`,调用 `srei_parse_lib` 解析完整的 ELF 头部。与 `link_map` 快路径相比,这里需要完整实现 ELF 头部解析、程序头遍历、`PT_DYNAMIC` 定位等步骤,代码路径更长,但兼容性更好。

回退路径的性能开销略高于快路径,但考虑到符号解析发生在 Loader 启动阶段,且通常只需要执行一次,这个开销完全可以接受。

## libc 识别与优先搜索

Loader 通过文件名的基础名称(basename)模式匹配来识别 libc 的类型和版本:

- `libc-*` 模式:匹配 glibc 的版本化文件名(如 `libc-2.17.so`、`libc-2.31.so`)
- `libc.so*` 模式:匹配 glibc 的符号链接文件名(如 `libc.so.6`)
- `ld-musl-*` 模式:匹配 musl 的动态链接器(如 `ld-musl-x86_64.so.1`),在 musl 中 libc 功能内置在动态链接器中

识别完成后,Loader 将 libc 条目交换到缓存数组的索引 0 位置。后续的符号查找优先搜索索引 0,因为绝大多数符号查找(malloc、free、strlen、printf 等)都命中 libc。这个优化避免了每次符号查找都遍历全部已加载库的开销。

## libc_idx 边界处理

libc 优先搜索引入了一个微妙的边界条件。当 `libc_idx == 0` 时(未识别到 libc),符号查找循环必须从索引 0 开始:

```c
uint32_t start = r->libc_idx ? 1 : 0;
for (uint32_t i = start; i < r->nlibs; i++) {
    if (srei_lookup_sym(r->libs[i], hash, name))
        return found;
}
```

当 `libc_idx > 0` 时,libc 已被交换到 `libs[0]`,在进入循环之前已经单独检查过 `libs[0]`,因此循环从索引 1 开始以避免重复查找。当 `libc_idx == 0` 时,没有单独检查过任何库,循环必须从索引 0 开始,否则会跳过第一个库。这个看似简单的条件判断,如果处理不当,会导致某些共享库中的符号查找遗漏。

## DT_NEEDED 三级 dlopen 查找

对于包含 `DT_NEEDED` 依赖项的 `.so` 文件(例如依赖 libz 进行压缩解压),Loader 需要通过 `dlopen` 加载这些依赖库。在自解析模式下,获取 `dlopen` 函数指针本身就是一个挑战。Loader 实现了三级查找策略:

**第一级:libdl.so dlopen**: 适用于 glibc 2.17 至 2.33 版本。在这些版本中,`dlopen` 由独立的 `libdl.so` 共享库导出。Loader 通过前面建立的已加载库列表,在 `libdl.so` 中查找 `dlopen` 符号。

**第二级:libc __libc_dlopen_mode**: 适用于 glibc 2.34 及更高版本。从 2.34 开始,glibc 将 `libdl.so` 合并到 `libc.so` 中,`dlopen` 不再作为公开符号导出,但 `__libc_dlopen_mode` 内部函数仍然可用。调用时需要传入 `__RTLD_DLOPEN`(0x80000000)标志,这是 glibc 内部的 RTLD 标志位。

**第三级:linker dlopen**: 适用于 Android/Bionic 环境。Bionic 的 `dlopen` 由 `linker64`(或 `linker`)提供,Loader 从其符号表中直接解析 `dlopen`。

**musl 的限制**: 在 musl 环境中,以上三级查找全部失败——musl 的 `dlopen` 实现未通过符号表暴露给自解析模式。这意味着依赖 `DT_NEEDED` 的 `.so` 在 musl 环境中无法自动加载其依赖库。但是,仅依赖 libc 的 `.so` 仍然可以正常工作,因为 musl 的 libc 功能已经在目标进程的地址空间中。
