# SREI 技术设计文档

本文面向了解 PE/COFF 结构的读者，阐述 SREI（Shellcode Reflective ELF Injection）的设计思路、ELF 关键结构以及每个阶段的处理方式。如果你熟悉 sRDI 如何将 DLL 转为 shellcode，本文将帮助你理解 Linux ELF 上的等价设计。

## 从 PE 到 ELF：反射加载的共性

反射加载（Reflective Loading）的核心思想是将一个动态链接库从内存中直接加载执行，而不依赖操作系统的加载器。在 Windows 上，sRDI 将 DLL（PE 格式）转换为一段自包含的 shellcode，该 shellcode 内嵌了一个微型加载器，能够自行解析 PE 头、处理重定位、解析导入符号、调用 DllMain。SREI 在 Linux 上做完全相同的事情，只是将目标从 PE 换成了 ELF。

ELF（Executable and Linkable Format）是 Linux 的可执行文件格式。一个共享库（.so）就是一个 ET_DYN 类型的 ELF 文件，它包含程序头表（Program Headers）、节头表（Section Headers）、动态段（PT_DYNAMIC）等结构。与 PE 的 NT_HEADERS、数据目录、导入表类似，ELF 也有自己的一套描述依赖关系和重定位信息的机制。

反射加载面临的根本问题是：如何在不调用 dlopen/dlsym（它们需要 libc）的情况下，将一段 ELF 数据变为可执行的内存映像？SREI 的回答是：不在运行时解析 ELF。而是在打包阶段（Python 端）将 ELF 预处理为一种更简单的中间格式（llbin），然后由一个极小的 PIC 加载器（约 3.8KB）在运行时加载这种中间格式。

这种两阶段设计与 sRDI 不同——sRDI 的 loader 在运行时解析 PE 头。我们选择预处理的理由是：ELF 的重定位处理比 PE 复杂得多（REL/RELA/JMPREL 三套表、IFUNC 间接函数、init_array 构造函数数组等），将解析工作前置到 Python 端可以让 loader 尽可能小，同时 Python 有完整的 ELF 解析能力。

## ELF 关键结构与 llbin 预处理

### Program Headers 和 LOAD 段

ELF 的 Program Header Table 描述了文件中的可加载段。PT_LOAD 段定义了需要映射到内存中的区域——包括文件偏移（p_offset）、虚拟地址（p_vaddr）、文件大小（p_filesz）、内存大小（p_memsz）和权限（p_flags，r/w/x）。一个典型的共享库有两个 PT_LOAD 段：第一个是代码段（r-x），第二个是数据段（rw-）。

在 llbin 预处理阶段，packer 读取所有 PT_LOAD 段，将它们重新拼接为一个连续的内存映像（image），并将所有虚拟地址转换为相对于映像起始的偏移。这样做的好处是：loader 只需一次 mmap + memcpy，而不需要像内核加载器那样分别映射每个段。代价是初始时所有页面都是 RW（可读写），需要在加载完成后通过 mprotect 分别设置权限。llbin 的段表（segment table）记录了每个段在映像中的偏移、大小和权限，供 loader 做最终的保护设置。

### Dynamic Segment（PT_DYNAMIC）

PT_DYNAMIC 段是 ELF 共享库的核心元数据来源。它是一个由 Elf64_Dyn 结构组成的数组，每个元素包含一个标签（d_tag）和一个值（d_val）。关键的标签包括：DT_STRTAB（动态字符串表地址）、DT_SYMTAB（动态符号表地址）、DT_STRSZ（字符串表大小）、DT_RELA/DT_REL（重定位表地址和大小）、DT_JMPREL（PLT 重定位表）、DT_INIT_ARRAY/DT_FINI_ARRAY（构造/析构函数数组）等。

在 packer 阶段，我们遍历 PT_DYNAMIC 中的所有条目，提取重定位表、符号表、字符串表等信息。这些信息被转换为 llbin 格式中的 fixup 表、import 表、init 表等。在运行时，loader 不需要再解析 PT_DYNAMIC——它直接操作 llbin 的表结构。

### DT_STRTAB 绝对地址与相对地址

一个重要的细节是 DT_STRTAB/DT_SYMTAB/DT_GNU_HASH 的地址处理。不同 C 运行时对 dynamic section 中的 d_val 处理不同：

- **glibc**：动态链接器（ld-linux.so）在加载共享库后，会将 DT_STRTAB、DT_SYMTAB 等条目的 d_val 从文件虚拟地址改写为运行时绝对地址。这意味着 loader 可以直接使用这些值作为指针。
- **musl**：动态链接器不会改写 in-memory 的 dynamic section。d_val 保持为文件中的原始虚拟地址（相对值）。loader 必须加上 load_bias 才能获得正确的绝对地址。

SREI 通过 `dyn_ptr()` 函数处理这种差异：

```c
static inline uintptr_t dyn_ptr(uint64_t d_val, uintptr_t load_bias) {
    if (d_val >= load_bias)
        return (uintptr_t)d_val;        // glibc: 已经是绝对地址
    return load_bias + (uintptr_t)d_val; // musl: 需要加 load_bias
}
```

逻辑是：如果 d_val 的值大于等于 load_bias（如 0x7f...），说明它已经被 patch 为绝对地址；否则它是相对地址，需要加上 load_bias。这个判断在两种情况下都正确。

### 符号表（.dynsym）和字符串表（.dynstr）

ELF 的动态符号表（.dynsym）是一个 Elf64_Sym 结构数组。每个符号包含名称偏移（st_name，相对于 .dynstr）、类型和绑定属性（st_info）、所在段索引（st_shndx）、值（st_value）和大小（st_size）。对于共享库中的导出函数，st_value 是函数在 ELF 虚拟地址空间中的地址（对于 PIC 库，通常从 0 开始的偏移）。对于导入的外部符号，st_shndx 为 SHN_UNDEF（0），st_value 为 0。

在 llbin 的 import 表中，我们只存储符号名字符串的偏移。loader 在运行时通过名称查找符号地址。对于自解析模式，查找通过 GNU hash table 或 SysV hash table 完成。

### GNU Hash Table、Bloom Filter 和 SysV Hash Table

GNU hash table 是 glibc 默认的符号查找加速结构。它由四个部分组成：头部（nbuckets、symoffset、bloom_size、bloom_shift）、Bloom filter（用于快速排除不存在的符号）、buckets 数组（每个 bucket 存储该 hash 槽中第一个符号的索引）和 chains 数组（存储每个符号的 hash 值，最低位作为终止标记）。

查找过程：计算符号名的 djb2 hash 值，先查 Bloom filter 做 O(1) 排除——取 bloom[(h/64) % bloom_size] 字，检查 (h%64) 和 ((h>>bloom_shift)%64) 两个位是否都为 1。如果 Bloom filter 排除，直接返回 NULL，无需查 bucket。如果 Bloom filter 通过，再取 bucket[hash % nbuckets] 得到起始符号索引，沿 chain 线性扫描。GNU hash 的优势是 O(1) 平均查找时间和更好的缓存局部性。

对于没有 GNU hash table 的库（如 musl libc 编译的库），我们回退到 SysV hash table（DT_HASH）。它的结构更简单：头部是 nbucket 和 nchain，后面是 bucket[] 和 chain[] 数组。查找时取 bucket[hash % nbucket] 得到符号索引，然后沿 chain[] 链表遍历。

### 重定位（Relocation）

重定位是反射加载中最复杂的部分。ELF 有三种重定位表：DT_RELA（带显式加数的重定位）、DT_REL（隐式加数的重定位）和 DT_JMPREL（PLT 重定位，用于延迟绑定）。

x86_64 架构上，SREI 处理五种重定位类型。R_X86_64_RELATIVE（类型 8）是基址重定位——加载地址与首选基址不同时，需要将指针加上偏移量（slide）。R_X86_64_64（类型 1）是绝对地址重定位——将 GOT 槽设为符号地址。R_X86_64_GLOB_DAT（类型 6）和 R_X86_64_JUMP_SLOT（类型 7）是 GOT/PLT 重定位——设置 GOT 条目为符号的实际地址。R_X86_64_IRELATIVE（类型 37）是 IFUNC 间接重定位——GOT 槽中存的是 resolver 函数的地址，需要调用该函数获取实际实现地址。

在 packer 阶段，所有重定位被分类为三类 fixup：REBASE（基址调整）、IMPORT（符号导入）和 IRELATIVE（间接函数）。这种分类让 loader 的处理逻辑极简化：REBASE 只需加 slide，IMPORT 只需查符号表，IRELATIVE 只需调用 resolver。

### IFUNC 间接函数（STT_GNU_IFUNC）

IFUNC 是 glibc 特有的扩展，允许在运行时根据 CPU 特性选择最优的函数实现。例如 memcpy 在 glibc 中不是一个普通函数，而是一个 IFUNC resolver——运行时它会检测 CPU 是否支持 AVX2/ERMS 等特性，然后返回对应的优化实现（如 memcpy_avx2、memcpy_sse2 等）。

这对反射加载有两个影响。第一，当 loader 在自解析模式下查找 memcpy 符号时，它在 libc 的 .dynsym 中找到的 st_value 指向的是 resolver 函数，而不是实际的 memcpy 实现。SREI 的解决方案是：在 srei_resolve_in_lib 中检测符号类型（st_info 的低 4 位），如果是 STT_GNU_IFUNC（类型 10），则先调用 resolver，使用其返回值作为实际地址。

第二，IRELATIVE 重定位处理的是 .so 自身定义的 IFUNC。当 .so 的 GOT 中包含 IRELATIVE 条目时，loader 需要调用 .so 内部的 resolver 函数（地址 = 镜像基址 + addend），获取实际函数地址并写回 GOT。

### init_array 构造函数

ELF 的 DT_INIT_ARRAY 指向一个函数指针数组，这些函数在库被加载时按顺序调用（等价于 C++ 中 `__attribute__((constructor))` 或全局对象的构造函数）。packer 从 ELF 中提取 init_array 的所有条目，将它们转换为 llbin 的 init 表（每个条目是一个 64 位偏移）。loader 在完成所有重定位和段保护设置后，按顺序调用这些函数。这个顺序很重要——构造函数可能依赖已解析的符号（比如调用 printf），所以必须在 IMPORT fixup 之后调用。

### 导出函数与用户数据

llbin 的 export 表允许 loader 在加载完成后按名称哈希查找并调用一个导出函数。这个设计借鉴了 sRDI 的做法：shellcode 不仅加载 .so，还可以立即调用其中一个导出函数，并传入用户提供的任意数据。这在渗透场景中非常实用——你可以将命令、配置或另一个 payload 作为 user_data 嵌入 shellcode 尾部。

哈希算法使用 ROTR13（循环右移 13 位），与 sRDI 的 hash 函数相同。这个选择不是随意的——它足够简单（只有移位和加法），碰撞率可接受，而且在已知工具中广泛使用。

## Loader 设计：位置无关与系统调用

### PIC（位置无关代码）约束

SREI 的 loader 必须是位置无关的——它会被嵌入到 shellcode 中，在任意地址执行。这意味着：

不能使用全局变量（没有固定的 GOT 地址）。Loader 中的所有状态都通过参数传递或栈分配。例如 srei_resolver 结构体就完全在栈上分配。

不能使用标准库。Loader 通过内联汇编直接发起系统调用（syscall 指令），不链接任何 .so。syscall.h 封装了 mmap（9）、mprotect（10）、munmap（11）、open（2）、read（0）、close（3）等系统调用。x86_64 的系统调用号从 2.6 内核定义以来从未改变，这保证了跨版本兼容性。

不能使用字符串常量的常规寻址。但 GCC 的 -fPIC 选项会将字符串引用编译为 RIP-relative 寻址（lea rax, [rip+offset]），这天然是位置无关的。链接脚本将 .text.entry 段放在最前面（确保 srei_load 函数在 shellcode 的起始位置），然后是 .text 和 .rodata（字符串常量所在段）。最终 objcopy 提取 .text 和 .rodata 的原始字节作为 loader shellcode。

### 编译优化：-Os

Loader 使用 `-Os`（优化代码大小）而非 `-O2` 编译。实测效果显著：-O2 下 loader 为 5140 字节（编译器激进内联所有 static inline 函数，导致代码膨胀），-Os 下仅 2828 字节（合理选择内联/outline）。加上 musl 回退路径后最终为 3819 字节，仍比原 -O2 版本小 25.7%。

### Word-aligned memcpy

Loader 使用 8 字节 word 对齐的 memcpy 实现，而非逐字节复制。对于典型的 .so 镜像（10-100KB），复制速度提升约 8 倍。代价仅增加约 31 字节代码。

### Bootstrap：参数传递的桥梁

Shellcode 的调用者通常只需要跳转到起始地址（call 或 jmp），不会像正常函数那样传递参数。Bootstrap 代码（68 字节）负责：第一，通过 call $+5 / pop rax 技巧获取当前执行地址（这是经典的 shellcode PIC 技术）；第二，基于该地址计算 loader、llbin、user_data 的偏移；第三，设置 SysV AMD64 调用约定的六个寄存器参数和一个栈参数；第四，对齐栈到 16 字节边界（x86_64 ABI 要求）；第五，通过相对 call 跳转到 loader 入口。

Bootstrap 的所有指令大小是预先确定的（通过手动选择指令编码），所以 offset 计算可以在组装时完成，不需要运行时重定位。

## 自解析模式的设计

自解析是 SREI 最独特的功能——loader 在不调用 dlsym 的情况下，自行在进程的已加载库中查找符号。这个过程使用双路径策略，覆盖 glibc、musl 和 Android/Bionic 三大 C 运行时。

### 快路径：link_map（glibc / Android / Bionic）

这是首选路径，速度快、内存占用小：

1. 读取 `/proc/self/auxv`（~320 字节，栈上缓冲区）→ 找到 AT_BASE（动态链接器基址）
2. 解析 ld.so 的 ELF 头 → 在其符号表中查找 `_r_debug`（glibc 自 2.0 起导出此符号，ABI 从未改变）
3. 读取 `_r_debug.r_map`（偏移 +8）→ 遍历 `link_map` 链表

link_map 结构的前 5 个字段是 SVR4 调试器协议 ABI，在 glibc、musl、Bionic 上布局一致：

```c
struct link_map {
    uintptr_t l_addr;       // +0  load bias
    char      *l_name;      // +8  路径名
    Elf64_Dyn *l_ld;        // +16 直接指向 .dynamic 段!
    link_map  *l_next;      // +24
    link_map  *l_prev;      // +32
};
```

link_map 路径的关键优势是 `l_ld` 直接给出 dynamic section 指针，无需解析 ELF 头、找 PT_LOAD、找 PT_DYNAMIC。同时 `l_addr` 直接给出 load_bias。这省去了 `srei_parse_lib` 中最复杂的 ELF 头解析流程。

对于 Android/Bionic，此路径还从 ld.so（linker64）中额外解析 `dlopen` 符号，存入 `linker_dlopen`。因为 Android 上 dlopen 在 linker64 中而非 libdl.so 中。

### 回退路径：/proc/self/maps（musl / Alpine / OpenWrt）

当 link_map 路径失败时（musl 的 ld-musl 不导出 `_r_debug`），自动触发回退：

1. 读取 `/proc/self/maps`（8KB 栈上缓冲区，不使用 mmap）
2. 逐行解析，提取 .so 文件的基地址和路径
3. 路径去重（跳过同一 .so 的多个映射）
4. 对每个 .so 调用 `srei_parse_lib` 解析完整 ELF 头

### libc 识别与优先搜索

通过文件名 basename 匹配识别 libc：

- `libc-*`：glibc（如 libc-2.17.so）
- `libc.so*`：glibc（如 libc.so.6）
- `ld-musl-*`：musl（如 ld-musl-x86_64.so.1，libc 功能内置其中）

识别后，libc 被交换到缓存数组索引 0，优先搜索。因为绝大多数符号查找都命中 libc，这避免了每次查找都遍历所有库。

### 符号查找循环的 libc_idx 处理

一个微妙但关键的边界情况：当 libc_idx == 0（未识别出 libc）时，`srei_resolve` 的搜索循环必须从索引 0 开始（而非 1），否则 libs[0] 中的符号会被跳过：

```c
uint32_t start = r->libc_idx ? 1 : 0;
for (uint32_t i = start; i < r->nlibs; i++) { ... }
```

libc_idx > 0 时，libs[0] 已在上方单独检查过，循环从 1 开始避免重复。libc_idx == 0 时，libs[0] 未被检查，循环必须从 0 开始。

### DT_NEEDED 依赖加载的三级 dlopen 查找

对于有 DT_NEEDED 的 .so（如依赖 libz），loader 需要调用 dlopen 加载缺失的依赖。三级查找覆盖所有主流 C 运行时：

1. **libdl.so 的 dlopen**：glibc 2.17-2.33，存在独立的 libdl.so
2. **libc 的 `__libc_dlopen_mode`**：glibc 2.34+（libdl 合并入 libc），需要加 `__RTLD_DLOPEN`（0x80000000）标志
3. **linker dlopen**：Android/Bionic，dlopen 在 linker64 中

在 musl 上，三级查找都失败（musl 的 dlopen 不以上述任何方式暴露给自解析模式）。这意味着 DT_NEEDED 依赖不会被自动加载。对于只依赖 libc 的 .so（libc 已在进程中），仍可正常工作。

## 与 sRDI 的对比

| 方面 | sRDI | SREI |
|------|------|------|
| 目标格式 | PE DLL | ELF .so |
| 运行时解析 | Loader 解析 PE 头 | Python 预处理为 llbin |
| Loader 大小 | ~8KB | 3.8KB |
| 符号查找 | PEB → InLoadOrderModuleList | link_map + /proc/self/maps 双路径 |
| Hash 查找 | NamePointerTable 二分查找 | GNU hash (含 bloom filter) / SysV hash |
| IFUNC | 无（PE 没有 IFUNC 概念） | 需要处理 STT_GNU_IFUNC 和 IRELATIVE |
| 构造函数 | DllMain（单个入口） | init_array（多个入口） |
| 自解析 | 遍历 PEB（始终可用） | link_map（glibc/Android）或 /proc/self/maps（musl） |
| C 运行时兼容 | 仅 Windows | glibc 2.17+ / musl / Bionic |

最大的架构差异在于自解析的数据源。Windows 上 sRDI 通过 PEB（Process Environment Block）获取已加载模块列表，这是内核维护的数据结构，始终可访问。Linux 上 SREI 使用双路径策略：link_map（通过 `_r_debug` 访问动态链接器维护的链表，适用于 glibc 和 Bionic）和 /proc/self/maps（适用于 musl）。两种路径都失败时（如无 /proc 的极端容器），调用者需提供 dlsym_fn。

## 已知限制与未来方向

符号版本（DT_VERNEED/DT_VERSYM）是一个兼容性缺口。glibc 使用符号版本机制来保证向后兼容（如 memcpy@@GLIBC_2.2.5）。当前 SREI 忽略版本信息，按名称匹配。在大多数情况下这不会出问题，因为同一版本的 libc 中通常只有一个版本的给定符号。但在跨版本场景中可能出错。

TLS（Thread-Local Storage）支持是另一个重要的缺失特性。如果 .so 使用了 __thread 变量或 C++ thread_local，loader 需要：识别 PT_TLS 段，为 TLS 区分配内存，处理 DTPMOD/DTPOFF/TPOFF 等重定位类型。这涉及到内核接口（arch_prctl ARCH_SET_FS）和运行时约定的配合，实现复杂度较高。

C++ 异常处理（.eh_frame）也是一个缺失。.so 中的 .eh_frame 段包含了栈展开信息，用于 C++ 异常的 throw/catch。这些信息通常需要在加载时通过 `__register_frame` 注册。未注册时，异常传播会失败（terminate）。对于纯 C .so，这不是问题。
