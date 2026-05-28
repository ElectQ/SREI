# ELF 关键结构与 llbin 预处理

本文是 SREI（Shellcode Reflective ELF Injection）系列文档的第二篇，面向希望深入理解共享库（.so）如何被转换为 llbin 中间格式的读者。我们将逐一拆解 ELF 中与反射加载相关的关键结构，说明 Packer 如何提取每种结构的信息，以及 llbin 格式如何以更简洁的方式组织这些数据，使 Loader 在运行时无需解析 ELF。

## PE-ELF 结构对照表

SREI 的设计灵感来自 Windows 平台的 sRDI。如果你已经熟悉 PE 格式中反射加载相关的结构，下面的对照表可以帮助你快速建立 ELF 中的对应关系：

| PE 结构 | ELF 对应 | 说明 |
|---|---|---|
| IMAGE_SECTION_HEADER | Elf64_Phdr (PT_LOAD) | 可加载段 |
| IMAGE_IMPORT_DESCRIPTOR | DT_NEEDED + DT_STRTAB + .dynsym | 导入描述 |
| IMAGE_THUNK_DATA (IAT) | GOT 条目 + Elf64_Rela | 导入地址槽 |
| IMAGE_BASE_RELOCATION | REBASE fixup (slide adjustment) | 基址重定位 |
| IMAGE_EXPORT_DIRECTORY | .dynsym (st_shndx != 0) + export 表 | 导出描述 |
| DllMain 入口 | DT_INIT_ARRAY 函数指针数组 | 初始化入口 |

PE 中每个 section header 直接描述一个节区的属性，而 ELF 的 PT_LOAD Program Header 描述的是可加载的内存段——一个段可能包含多个节区。PE 的 IMAGE_IMPORT_DESCRIPTOR 通过名称字符串直接引用 DLL，ELF 则通过 DT_NEEDED 声明依赖库名，再由 .dynsym 中的未定义符号（st_shndx == SHN_UNDEF）表达具体的导入需求。PE 的 IAT 是一个函数指针数组，ELF 的 GOT（Global Offset Table）扮演类似角色，每个 GOT 条目对应一个需要运行时填充的地址槽。

## Program Headers 和 LOAD 段

ELF 的 Program Header Table 描述文件中所有可加载段的布局。每个 PT_LOAD 段包含以下关键字段：p_offset（文件内偏移）、p_vaddr（虚拟地址）、p_filesz（文件中的大小）、p_memsz（内存中的大小）和 p_flags（权限标志）。p_memsz 可能大于 p_filesz，差值部分在加载时由内核零填充——这就是 .bss 段的来源。

典型的 .so 文件有两个 PT_LOAD 段：第一个是代码段（权限 r-x），包含 .text、.rodata 等节区；第二个是数据段（权限 rw-），包含 .data、.bss、.got 等。某些库可能有第三个 PT_LOAD 段，用于将只读数据与代码分离。

在 Packer 阶段，所有 PT_LOAD 段被读取并重新拼接为一个连续的内存映像（image）。拼接过程中，所有虚拟地址被转换为相对于映像起始的偏移。这样做的好处是 Loader 只需一次 mmap + memcpy 即可完成整个镜像的加载，而不需要像内核加载器那样对每个段分别映射到不同的虚拟地址。代价是初始时所有页面都是 RW（可读写），需要在加载完成后通过 mprotect 对每个段分别设置正确的权限。llbin 的段表（segment table）记录了每个段在映像中的偏移、大小和最终权限，供 Loader 做最终的保护设置。

**权限编码细节：** 这是一个容易忽视但会导致段错误的细节。ELF 标准中 p_flags 的权限位定义为 PF_R=4、PF_W=2、PF_X=1，而 Linux 内核 mprotect 系统调用的权限常量是 PROT_READ=1、PROT_WRITE=2、PROT_EXEC=4——两组常量的位排列恰好相反。Packer 在写入 llbin 段表时执行一次性转换：`prot = (flags>>2)&1 | (flags>>1)&2 | (flags<<2)&4`。这意味着 Loader 在运行时直接将 llbin 中存储的 prot 值传给 mprotect，无需做任何运行时转换，减少了一个潜在的错误源。

## Dynamic Segment (PT_DYNAMIC)

PT_DYNAMIC 段是 ELF 共享库的核心元数据来源。它是一个由 Elf64_Dyn 结构组成的数组，每个元素包含一个标签（d_tag，类型 int64_t）和一个联合值（d_val / d_ptr，类型 uint64_t）。数组以 DT_NULL（d_tag == 0）结尾。

与反射加载密切相关的关键标签包括：DT_STRTAB（动态字符串表地址）、DT_SYMTAB（动态符号表地址）、DT_STRSZ（字符串表大小）、DT_RELA 和 DT_RELASZ（显式加数重定位表及其大小）、DT_REL 和 DT_RELSZ（隐式加数重定位表）、DT_JMPREL 和 DT_PLTRELSZ（PLT 重定位表）、DT_INIT_ARRAY 和 DT_INIT_ARRAYSZ（构造函数指针数组）、DT_FINI_ARRAY 和 DT_FINI_ARRAYSZ（析构函数指针数组）、DT_NEEDED（依赖库名称在字符串表中的偏移）、DT_GNU_HASH（GNU hash 表地址）和 DT_HASH（SysV hash 表地址）。

Packer 遍历 PT_DYNAMIC 中的所有条目，提取重定位表、符号表、字符串表、构造/析构函数数组等信息，然后将它们转换为 llbin 格式中的 fixup 表、import 表、init 表、fini 表等。在运行时，Loader 完全不需要解析 PT_DYNAMIC——它直接操作 llbin 的表结构。这是 SREI 采用预处理架构的核心动机：将所有 ELF 结构解析工作前置到 Python 端，换取更小的 Loader 和更简单的运行时逻辑。

## DT_STRTAB 绝对地址与相对地址

DT_STRTAB、DT_SYMTAB、DT_GNU_HASH 等标签的 d_val 存储的是地址值，但这个地址在不同 C 运行时下的含义不同。这是一个在 glibc 和 musl 之间存在行为差异的关键细节。

**glibc** 的动态链接器（ld-linux.so）在加载共享库之后，会将 dynamic section 中 DT_STRTAB、DT_SYMTAB 等条目的 d_val 从文件中的虚拟地址改写为运行时绝对地址。这意味着在运行时读取这些 d_val，可以直接将其当作指针使用。

**musl** 的动态链接器不会改写 in-memory 的 dynamic section。d_val 保持为文件中的原始虚拟地址（相对值，通常是一个较小的数值如 0x400）。Loader 必须将 d_val 加上 load_bias 才能获得正确的绝对地址。

SREI 通过 `dyn_ptr()` 函数优雅地处理这种差异：

```c
static inline uintptr_t dyn_ptr(uint64_t d_val, uintptr_t load_bias) {
    if (d_val >= load_bias)
        return (uintptr_t)d_val;        // glibc: 已经是绝对地址
    return load_bias + (uintptr_t)d_val; // musl: 需要加 load_bias
}
```

判断逻辑是：如果 d_val 的值大于等于 load_bias（如 0x7f... 量级的地址），说明它已经被 glibc 的动态链接器 patch 为绝对地址，直接返回即可。否则它是文件中的原始相对地址，需要加上 load_bias。这个判断在 glibc 和 musl 两种情况下都能正确工作，无需运行时检测 C 运行时类型。

## 符号表 (.dynsym) 和字符串表 (.dynstr)

ELF 的动态符号表（.dynsym）是一个 Elf64_Sym 结构数组。每个 Elf64_Sym 占 24 字节，包含以下字段：st_name（符号名在 .dynstr 中的偏移，4 字节）、st_info（类型和绑定属性，1 字节）、st_other（可见性，1 字节）、st_shndx（所在段索引，2 字节）、st_value（符号值，8 字节）和 st_size（符号大小，8 字节）。

对于共享库中的**导出函数**，st_value 是函数在 ELF 虚拟地址空间中的偏移（PIC 库通常从 0 开始计算），st_shndx 不为 SHN_UNDEF（0），表示该符号在当前库中有定义。对于**导入的外部符号**，st_shndx 为 SHN_UNDEF（0），st_value 为 0，表示该符号需要从其他库中解析。

在 llbin 的 import 表中，Packer 只存储符号名字符串在 llbin 字符串表中的偏移。Loader 在运行时通过符号名称在已加载库中查找其地址。在 llbin 的 export 表中，Packer 存储符号名称偏移和地址偏移，Loader 使用 ROTR13 哈希按名称查找导出函数。

## GNU Hash Table、Bloom Filter 和 SysV Hash Table

符号查找的性能直接影响 Loader 的启动速度。ELF 提供两种 hash 表结构来加速符号查找。

**GNU Hash Table**（DT_GNU_HASH）是 glibc 默认的符号查找加速结构。它由四个连续的部分组成：头部（4 个 uint32_t：nbuckets、symoffset、bloom_size、bloom_shift）、Bloom filter（bloom_size 个 uint64_t）、buckets 数组（nbuckets 个 uint32_t）和 chains 数组（变长）。

查找过程分为三步。第一步，计算符号名的 djb2 hash 值。第二步，检查 Bloom filter 做 O(1) 排除：取 `bloom[(h/64) % bloom_size]` 字，检查 `(h%64)` 和 `((h>>bloom_shift)%64)` 两个位是否都为 1。如果任一位为 0，该符号肯定不存在于当前库中，直接返回 NULL，无需查 bucket。Bloom filter 的设计使得绝大多数不存在的符号在这一步就被排除，避免了昂贵的字符串比较。第三步，如果 Bloom filter 通过，取 `bucket[hash % nbuckets]` 得到起始符号索引（如果为 0 表示空桶），沿 chain 数组线性扫描。chain 中每个条目的最低位作为终止标记：为 1 表示该桶中最后一个符号，为 0 表示还有后继。GNU hash 的核心优势在于 Bloom filter 带来的 O(1) 负查找能力和更好的缓存局部性。

**SysV Hash Table**（DT_HASH）是更简单的传统结构，通常在 musl libc 编译的库中出现。它由四部分组成：头部（nbucket + nchain，各 uint32_t）、bucket 数组（nbucket 个 uint32_t）和 chain 数组（nchain 个 uint32_t）。查找时取 `bucket[hash % nbucket]` 得到符号索引，然后沿 chain[] 链表遍历，直到找到匹配或回到 0。SysV hash 没有 Bloom filter，每次查找至少需要访问一次 bucket。

SREI 的自解析模块优先使用 GNU hash table。如果目标库没有 DT_GNU_HASH（例如 musl 编译的库），则自动回退到 SysV hash table（DT_HASH）。这种双路径策略确保了在 glibc 和 musl 环境下都能正确查找符号。

## 重定位 (Relocation)

重定位是反射加载中最复杂的部分。ELF 有三种重定位表：DT_RELA（带显式加数的重定位，每个 Elf64_Rela 包含 r_offset、r_info 和 r_addend 三个字段）、DT_REL（隐式加数的重定位，每个 Elf64_Rel 只有 r_offset 和 r_info，加数隐式存储在被重定位的位置）和 DT_JMPREL（PLT 重定位，用于延迟绑定，格式可以是 REL 或 RELA）。

x86_64 架构上，SREI 处理八种重定位类型：

- **R_X86_64_RELATIVE**（类型 8）：基址重定位。当 .so 被加载到与首选基址不同的地址时，所有 RELATIVE 类型的 GOT/数据槽需要加上偏移量（slide = 实际加载地址 - 首选基址）。处理方式：`*slot += slide`。这是数量最多的重定位类型，一个典型的 .so 可能有数百到数千个 RELATIVE 条目。
- **R_X86_64_64**（类型 1）：绝对地址重定位。将 GOT 槽设置为解析后的符号绝对地址。处理方式：`*slot = symbol_address`。
- **R_X86_64_GLOB_DAT**（类型 6）：GOT 重定位。语义与 R_X86_64_64 基本相同，将 GOT 条目设置为符号的实际地址。
- **R_X86_64_JUMP_SLOT**（类型 7）：PLT 重定位。用于延迟绑定的函数调用，将 GOT 条目设置为符号的实际地址，使得后续通过 PLT 的调用直接跳转到目标函数。
- **R_X86_64_IRELATIVE**（类型 37）：IFUNC 间接重定位。GOT 槽中存储的不是符号地址，而是 resolver 函数的地址。Loader 需要调用该 resolver 获取实际的函数实现地址，然后写回 GOT。
- **R_X86_64_DTPMOD64**（类型 16）：TLS 模块 ID 重定位。将 GOT 槽设置为当前模块的 TLS 模块 ID。
- **R_X86_64_DTPOFF64**（类型 17）：TLS 块内偏移重定位。用于计算 `__thread` 变量在其所属 TLS 块内的偏移。
- **R_X86_64_TPOFF64**（类型 18）：TLS 线程指针偏移重定位。将 GOT 槽设置为 TLS 变量相对于线程指针（TP）的偏移。

在 Packer 阶段，这八种 ELF 重定位类型被分类为五类 fixup：REBASE（基址调整，对应 RELATIVE）、IMPORT（符号导入，对应 64/GLOB_DAT/JUMP_SLOT）、IRELATIVE（间接函数，对应 IRELATIVE）、TLS_MODULE（TLS 模块 ID，对应 DTPMOD64）和 TLS_OFFSET（TLS 偏移，对应 DTPOFF64 和 TPOFF64）。这种分类使得 Loader 的处理逻辑大幅简化——Loader 不需要理解八种 ELF 重定位类型的细节，只需处理五种语义明确的 fixup 操作。

## IFUNC 间接函数 (STT_GNU_IFUNC)

IFUNC（Indirect Function）是 glibc 特有的扩展机制，允许在运行时根据 CPU 特性选择最优的函数实现。这个机制在 PE 中没有对应物。

一个经典的例子是 memcpy。在 glibc 中，memcpy 不是一个普通的函数，而是一个 IFUNC resolver。当动态链接器解析 memcpy 符号时，它首先调用 resolver 函数，该函数检测当前 CPU 是否支持 AVX2、ERMS（Enhanced REP MOVSB/STOSB）等特性，然后返回对应的优化实现（如 memcpy_avx2、memcpy_erms 或 memcpy_sse2）。

IFUNC 对反射加载有两个层面的影响：

第一，当 Loader 在自解析模式下查找 memcpy 等外部符号时，它在 libc 的 .dynsym 中找到的 st_value 指向的是 resolver 函数，而不是实际的 memcpy 实现。SREI 的解决方案是：在 `srei_resolve_in_lib` 中检测符号类型（st_info 的低 4 位），如果是 STT_GNU_IFUNC（类型 10），则先调用 resolver 函数，使用其返回值作为实际的符号地址。

第二，IRELATIVE 重定位处理的是 .so 自身定义的 IFUNC。当 .so 的代码中使用 `__attribute__((ifunc))` 或编译器生成了 IFUNC（如静态链接的 memcpy），GOT 中会包含 IRELATIVE 条目。Loader 需要调用 .so 内部的 resolver 函数（地址 = 镜像基址 + addend），获取实际函数地址并写回 GOT。IRELATIVE fixup 在所有 IMPORT fixup 之后处理，因为 resolver 函数本身可能依赖已解析的 GOT 条目。

## init_array / fini_array 构造函数

ELF 的 DT_INIT_ARRAY 指向一个函数指针数组，这些函数在库被加载时按顺序调用。它们等价于 GCC 的 `__attribute__((constructor))` 或 C++ 中全局对象的构造函数。相应地，DT_FINI_ARRAY 指向析构函数数组，在库被卸载时调用。

Packer 从 ELF 中提取 DT_INIT_ARRAY 的所有条目，将每个函数指针（64 位虚拟地址）转换为相对于映像起始的偏移，写入 llbin 的 init 表。类似地，DT_FINI_ARRAY 的条目被提取到 fini 表中。

Loader 的调用顺序至关重要：先完成所有 fixup（REBASE → IMPORT → IRELATIVE → TLS_MODULE → TLS_OFFSET），然后初始化 TLS（分配 TLS 块、复制 init image），接着注册 .eh_frame（如果有），再对段执行 mprotect 设置正确的权限，最后按顺序调用 init_array 中的构造函数。这个顺序保证了构造函数执行时，所有 GOT 条目已解析完毕、TLS 变量可访问、C++ 异常处理已就绪、段权限已正确设置。如果顺序错误——例如在 IMPORT fixup 之前调用构造函数——构造函数中调用的 printf 等函数将跳转到未解析的 GOT 条目，导致段错误。

## 导出函数与 ROTR13 哈希

llbin 的 export 表允许 Loader 在加载完成后按名称哈希查找并调用一个导出函数。这个设计直接借鉴了 sRDI 的做法：shellcode 不仅加载 .so，还可以立即调用其中一个导出函数，并传入用户提供的任意数据。

在实际使用场景中，SREI 的 shellcode 由四部分拼接而成：Bootstrap（68 字节）+ Loader（5296 字节）+ llbin 数据 + user_data。当 Loader 完成所有加载工作后，它会计算目标导出函数名的 ROTR13 哈希，在 export 表中查找匹配的条目，获取函数地址并调用，传入 user_data 的指针和长度。user_data 是任意字节序列，嵌入在 shellcode 尾部，调用时以 `(const void *data, uint32_t len)` 的形式传递。这在渗透场景中非常实用——可以将命令、配置或另一个 payload 作为 user_data 嵌入。

哈希算法使用 ROTR13（Rotate Right 13 bits），与 sRDI 的 hash 函数完全相同。其实现极为简洁：

```c
static inline uint32_t srei_hash_name(const char *name) {
    uint32_t hash = 0;
    const unsigned char *p = (const unsigned char *)name;
    do {
        hash = ROTR32(hash, 13);
        hash += *p;
        p++;
    } while (*(p - 1) != 0);
    return hash;
}
```

选择 ROTR13 的原因是：它足够简单（只有循环右移和加法两条运算），碰撞率在符号名称长度范围内可接受（32 位哈希在数千个符号的表中很少碰撞），而且在 sRDI 等已知工具中广泛使用，便于交叉参考。

## llbin v5 格式定义

llbin 是 SREI 定义的中间格式，承载了从 ELF 中提取的所有加载所需信息。以下是其完整的数据结构定义，来源于 packer/llbin.h。

### llbin_header（128 字节）

整个 llbin 文件以一个固定 128 字节的头部开始，包含 29 个字段：

| 字段 | 偏移 | 大小 | 说明 |
|------|------|------|------|
| magic | 0 | 4 | 魔数，固定值 0x4E424C4C（ASCII "LLBN"） |
| version | 4 | 4 | 格式版本号，当前为 5 |
| arch | 8 | 4 | 目标架构（1=x86_64） |
| flags | 12 | 4 | 标志位（SREI_CLEARHEADER=0x1, SREI_CLEARMEMORY=0x2） |
| entry_off | 16 | 8 | 导出函数入口在映像中的偏移 |
| image_size | 24 | 8 | 完整映像大小（字节） |
| preferred_base | 32 | 8 | 首选加载基址（用于计算 slide） |
| image_off | 40 | 4 | 映像数据在 llbin 文件中的偏移 |
| fixup_off | 44 | 4 | fixup 表偏移 |
| fixup_count | 48 | 4 | fixup 条目数 |
| import_off | 52 | 4 | import 表偏移 |
| import_count | 56 | 4 | import 条目数 |
| strings_off | 60 | 4 | 字符串表偏移 |
| strings_size | 64 | 4 | 字符串表大小 |
| seg_count | 68 | 4 | 段表条目数（紧跟 header 之后） |
| init_off | 72 | 4 | init 表偏移 |
| init_count | 76 | 4 | init 条目数 |
| export_off | 80 | 4 | export 表偏移 |
| export_count | 84 | 4 | export 条目数 |
| needed_off | 88 | 4 | needed 表偏移（DT_NEEDED 依赖库名称） |
| needed_count | 92 | 4 | needed 条目数 |
| fini_off | 96 | 4 | fini 表偏移 |
| fini_count | 100 | 4 | fini 条目数 |
| eh_frame_off | 104 | 4 | .eh_frame 数据偏移 |
| eh_frame_size | 108 | 4 | .eh_frame 数据大小 |
| tls_init_off | 112 | 4 | TLS init image 偏移 |
| tls_init_size | 116 | 4 | TLS init image 大小 |
| tls_total_size | 120 | 4 | TLS 总大小（含 .tbss） |
| tls_align | 124 | 4 | TLS 对齐要求 |

所有偏移字段都是相对于 llbin 文件起始的字节偏移。Loader 通过 mmap 将整个 llbin 数据映射到内存后，直接使用这些偏移定位各个表。

### llbin_fixup（16 字节）

```c
struct llbin_fixup {
    uint32_t offset;     // 需要修复的 GOT/数据槽在映像中的偏移
    uint8_t  type;       // fixup 类型
    uint8_t  reserved;   // 保留，对齐用
    uint16_t import_idx; // 关联的 import 表索引（仅 IMPORT 类型使用）
    int64_t  addend;     // 加数（REBASE 存 slide, IRELATIVE 存 resolver 偏移）
};
```

fixup 类型定义如下：

| 值 | 名称 | 处理方式 |
|----|------|----------|
| 0 | REBASE | `*(base + offset) += slide` |
| 1 | IMPORT | `*(base + offset) = resolve(import_name)` |
| 2 | IRELATIVE | `*(base + offset) = ((resolver_fn)(base + addend))()` |
| 3 | TLS_MODULE | `*(base + offset) = tls_module_id`（固定为 1） |
| 4 | TLS_OFFSET | `*(base + offset) = tls_block_base + addend` |

### llbin_import（8 字节）

```c
struct llbin_import {
    uint32_t name_off;   // 符号名称在字符串表中的偏移
    uint32_t flags;      // 标志位（保留）
};
```

每个 import 条目代表一个需要从外部库解析的符号。Loader 通过符号名称在进程已加载的库中查找其地址，查找使用 GNU hash 或 SysV hash。

### llbin_segment（16 字节）

```c
struct llbin_segment {
    uint32_t offset;     // 段在映像中的偏移
    uint32_t size;       // 段大小
    uint32_t prot;       // 权限（已转换为 mprotect 格式：PROT_READ|PROT_WRITE|PROT_EXEC）
    uint32_t pad;        // 对齐填充
};
```

段表紧跟在 128 字节 header 之后，记录了映像中各个内存段的布局和权限。Loader 在完成所有重定位后，遍历段表对每个段执行 mprotect。段表中还可能包含 LLBIN_SEG_RELRO（0x100）标志，表示该段在重定位完成后应标记为只读（PT_GNU_RELRO 区域，通常是 GOT 的部分）。

### llbin_init（8 字节）

```c
struct llbin_init {
    uint64_t offset;     // 构造函数在映像中的偏移
};
```

每个 init 条目是一个 64 位偏移，指向映像中的一个构造函数。Loader 在完成所有 fixup 和段保护设置后，按顺序调用这些函数。

### llbin_export（16 字节）

```c
struct llbin_export {
    uint32_t name_off;   // 导出函数名称在字符串表中的偏移
    uint32_t flags;      // 标志位（保留）
    uint64_t addr_off;   // 导出函数在映像中的地址偏移
};
```

Loader 使用 ROTR13 哈希在 export 表中查找目标导出函数。找到后，以 `base + addr_off` 计算函数的实际地址并调用。

---

以上是 llbin 中间格式的完整定义。通过这种预处理架构，SREI 将 ELF 结构解析的复杂性完全封装在 Python 端的 Packer 中，使得 Loader 仅需约 5KB 的代码即可完成内存加载、重定位修复、TLS 初始化、C++ 异常支持等全部工作。下一篇文档将深入 Loader 的实现细节，包括 PIC 约束、系统调用封装、Bootstrap 参数传递以及自解析模式的双路径策略。
