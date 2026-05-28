# SREI 设计理念与架构概览

SREI（Shellcode Reflective ELF Injection）是一个将 Linux 共享库（`.so`）转换为位置无关 shellcode 的工具。它的设计灵感来源于 Windows 平台上著名的 sRDI（Shellcode Reflective DLL Injection），但针对 ELF 格式和 Linux 运行时环境进行了重新设计。本文档将从概念映射、核心问题、架构选择和技术对比等方面，全面阐述 SREI 的设计理念。

本文的目标读者是已经理解 PE/COFF 结构和 sRDI 工作原理的安全研究人员，通过建立 PE 与 ELF 之间的概念桥梁，帮助读者快速理解 SREI 的设计动机和技术取舍。

---

## PE-ELF 概念对照表

如果你已经熟悉 Windows 平台的 PE 加载机制，下表可以帮助你快速建立对 ELF 对应概念的理解：

| PE/Windows 概念 | ELF/Linux 对应 | 说明 |
|---|---|---|
| PE DLL (.dll) | ELF Shared Object (.so) | 动态链接库 |
| IMAGE_DOS_HEADER + IMAGE_NT_HEADERS | Elf64_Ehdr | 文件头 |
| OptionalHeader.DataDirectory[] | PT_DYNAMIC (Elf64_Dyn 数组) | 动态信息 |
| IMAGE_IMPORT_DESCRIPTOR | DT_NEEDED + IMPORT fixup | 导入表 |
| IMAGE_EXPORT_DIRECTORY | .dynsym 导出符号 (st_shndx != SHN_UNDEF) | 导出表 |
| IMAGE_BASE_RELOCATION | DT_RELA/DT_REL → REBASE fixup | 基址重定位 |
| DllMain | DT_INIT_ARRAY (init_array) | 入口函数 |
| IAT (Import Address Table) | GOT (Global Offset Table) | 导入地址表 |
| PEB → InLoadOrderModuleList | link_map 链表 | 已加载模块列表 |
| LoadLibrary / GetProcAddress | dlopen / dlsym | 运行时加载 |
| IMAGE_TLS_DIRECTORY | PT_TLS 段 | TLS |

PE 和 ELF 的核心差异在于：PE 使用单一的数据目录数组（`DataDirectory[]`）来索引各种表，结构统一且顺序固定；而 ELF 使用 `PT_DYNAMIC` 段中的 `Elf64_Dyn` 键值对来描述动态信息，每个条目由 `d_tag` 标识类型、`d_un` 存储值，解析方式更像遍历一个属性列表。此外，PE 的重定位模型相对统一（只有一种 `IMAGE_BASE_RELOCATION` 类型），而 ELF 的重定位类型多达数十种（x86_64 上就有 `R_X86_64_RELATIVE`、`R_X86_64_GLOB_DAT`、`R_X86_64_JUMP_SLOT`、`R_X86_64_IRELATIVE` 等），这也是 SREI 在设计上选择预处理策略的关键原因之一。

---

## 从 PE 到 ELF：反射加载的共性

反射加载（Reflective Loading）的核心思想是：在不依赖操作系统加载器（`LoadLibrary` / `dlopen`）的情况下，从内存中手动加载并执行一个动态链接库。这种技术之所以可行，是因为动态链接库本质上是一段包含元数据（重定位表、导入表、导出表等）的机器码。只要我们自己实现加载器的逻辑——分配内存、映射段、处理重定位、解析导入、调用初始化函数——就能绕过操作系统的加载机制。

在 Windows 上，sRDI 将 PE DLL 转换为一段独立的 shellcode。这段 shellcode 包含了一个微型加载器，它在目标进程中运行时，自行解析 PE 头部信息，完成 DLL 的加载并调用 `DllMain`。整个过程不触碰磁盘，不调用 `LoadLibrary`，对所有安全检测完全透明。

SREI 在 Linux 上实现同样的目标。它将 ELF `.so` 文件转换为 shellcode，这段 shellcode 在目标进程中运行时，完成共享库的内存加载、重定位修复、符号解析和构造函数调用。两者的核心流程是一致的：

1. **获取自身地址**：shellcode 需要知道自己在内存中的位置，才能找到紧随其后的 payload 数据。
2. **分配可执行内存**：使用系统调用（Windows 上是 `VirtualAlloc`，Linux 上是 `mmap`）分配一块满足 RWX 权限的内存区域。
3. **映射段**：将库文件的各个 `PT_LOAD` 段按照文件偏移和虚拟地址映射到分配的内存中。
4. **修复重定位**：遍历重定位表，根据实际的加载基址修正所有需要重定位的地址。
5. **解析导入**：找到所需的共享库，查找并填充外部符号的实际地址。
6. **执行初始化**：调用库的入口函数或构造函数数组。
7. **调用导出函数**：根据用户指定的函数名（或哈希），查找并调用库的导出函数。

sRDI 在第 2-7 步中都需要运行时解析 PE 头部，这意味着 sRDI 的 loader 必须包含完整的 PE 解析逻辑。SREI 则采用了不同的策略——将 ELF 解析工作前置到编译时完成，运行时 loader 只需处理一个简化的中间格式。这一关键差异将在后文详细阐述。

---

## 核心问题与设计选择

### 根本问题

SREI 需要解决的根本问题是：**如何在不调用 `dlopen` / `dlsym` 的前提下，从内存中加载并执行一个 ELF 共享库。**

这个问题的约束条件非常严格：

- **无 libc 依赖**：Loader 运行在受限环境中，不能调用 `malloc`、`printf`、`dlopen` 等标准库函数，只能使用 Linux 系统调用（`syscall`）和少数通过宿主进程获得的函数指针（如 `dlsym`）。
- **位置无关**：Loader 本身必须是位置无关代码（PIC），因为它被注入到任意地址执行，不能包含任何绝对地址引用。
- **体积受限**：Shellcode 通常需要在网络传输或内存注入场景中使用，体积越小越好。
- **跨运行时兼容**：Linux 生态中存在多个 C 运行时实现（glibc、musl、Bionic），loader 必须在不同环境下都能正常工作。

### ELF 运行时解析的复杂性

如果像 sRDI 那样在运行时解析 ELF，loader 需要处理以下复杂情况：

**重定位表分散且多样**。ELF 将重定位信息分散在三个独立的表中：`DT_REL` / `DT_RELA`（普通重定位）、`DT_JMPREL`（PLT 跳转重定位）、以及它们与 `DT_SYMTAB`、`DT_STRTAB` 的交叉引用。每个重定位条目的类型决定了如何解析——x86_64 上有超过 30 种重定位类型，其中最常用的也有 8-10 种。相比之下，PE 只有 `IMAGE_BASE_RELOCATION` 一种基址重定位和 `IMAGE_THUNK_DATA` 一种导入重定位，模型简单得多。

**IFUNC 机制**。GNU IFUNC（`STT_GNU_IFUNC`）是一种间接函数解析机制，允许在运行时根据 CPU 特性选择最优的函数实现。IFUNC 通过 `R_X86_64_IRELATIVE` 重定位类型触发解析，解析器需要调用一个解析函数（resolver），该函数的地址本身就是重定位的目标。这意味着在重定位过程中，loader 必须能够执行代码来获取最终的函数地址。PE 没有等价机制。

**构造函数数组**。ELF 使用 `DT_INIT_ARRAY`（而非单个入口函数）来注册初始化函数，这是一个函数指针数组，需要按顺序逐一调用。在 glibc 中，`.init_array` 的调用时机在所有重定位完成之后，但如果某些 IFUNC resolver 依赖于已初始化的全局状态，顺序问题会更加复杂。PE 的 `DllMain` 则只有一个入口点，语义更简单。

**TLS 重定位**。线程局部存储（TLS）涉及 `PT_TLS` 段和 `__tls_get_addr` 函数。在 ELF 中，TLS 变量的访问通过 `TLSDESC` 或 `General Dynamic/Local Dynamic` 模型实现，需要在运行时分配 TLS 块并设置线程指针。PE 的 TLS 机制虽然也有（`IMAGE_TLS_DIRECTORY`），但在 shellcode 场景中较少涉及。

### SREI 的答案：预处理策略

面对上述复杂性，SREI 做出了一个关键的设计选择：**将 ELF 解析工作前置到打包阶段完成。**

具体而言，SREI 使用 Python 在打包时（pack time）完成所有 ELF 解析工作——读取段表、解析动态节区、提取重定位条目、分类符号——然后将结果编码为一个简化的中间格式（llbin）。运行时的 loader 只需要处理这个简化的 llbin 格式，无需理解 ELF 的完整语义。

这一策略的合理性基于以下观察：

1. **Python 有完整的 ELF 解析能力**。Python 生态中有 `pyelftools` 等成熟的 ELF 解析库，可以轻松处理所有 ELF 特有的复杂性（REL/RELA 区分、IFUNC 解析、符号版本等）。打包阶段运行在开发者的机器上，没有体积和运行时约束。

2. **Loader 运行在极端受限的环境中**。Loader 必须是位置无关的、不能依赖 libc、体积要尽量小。将复杂的解析逻辑塞进 loader 会导致体积膨胀（参考 sRDI 的 loader 约 8KB，即使只处理相对简单的 PE 格式），而且增加了跨运行时兼容性的风险。

3. **预处理可以优化运行时路径**。Python 可以在打包时做出一些优化决策，例如：跳过不需要的重定位条目、合并重定位类型、预计算符号哈希等。这些优化让运行时路径更短、更可预测。

通过这个设计选择，SREI 的 loader 最终只有 5296 字节——比 sRDI 的 loader 还小，尽管 ELF 的复杂度远高于 PE。

---

## 两阶段架构

SREI 的设计将整个转换流程分为两个阶段：打包阶段（pack time）和运行阶段（run time）。

### Stage 1：Python Packer

打包阶段由 `llpack.py` 实现，它的输入是一个标准的 ELF `.so` 文件，输出是 llbin 中间格式。

**核心流程：**

1. **读取 ELF 头部**：解析 `Elf64_Ehdr`，验证文件类型（必须是 `ET_DYN`），检查架构（必须是 x86_64）。
2. **提取 PT_LOAD 段**：遍历程序头表，找到所有 `PT_LOAD` 段。这些段定义了需要映射到内存中的数据。记录每个段的文件偏移、虚拟地址偏移、大小和权限标志。
3. **解析动态节区**：找到 `PT_DYNAMIC` 段，遍历其中的 `Elf64_Dyn` 条目，提取所有动态信息：`DT_NEEDED`（依赖库列表）、`DT_SYMTAB` / `DT_STRTAB`（符号表和字符串表）、`DT_RELA` / `DT_REL` / `DT_JMPREL`（重定位表）、`DT_INIT_ARRAY`（构造函数数组）、`DT_HASH` / `DT_GNU_HASH`（符号哈希表）等。
4. **处理重定位**：遍历所有重定位表，对每个重定位条目进行分类：
   - `R_X86_64_RELATIVE`：基址重定位，运行时只需加上加载基址。
   - `R_X86_64_GLOB_DAT` / `R_X86_64_JUMP_SLOT`：符号导入，运行时需要查找外部符号地址。
   - `R_X86_64_IRELATIVE`：IFUNC 间接重定向，运行时需要调用 resolver 获取最终地址。
   - 其他类型：按需处理。
5. **提取导出符号**：遍历 `.dynsym`，收集所有 `st_shndx != SHN_UNDEF` 的符号（即本库定义的符号），作为导出表。
6. **构建 llbin**：将上述所有信息编码为 llbin 格式——一个 128 字节的头部加上 image 数据和若干表（fixup 表、import 表、segment 表、init 表、export 表）。

### Stage 2：PIC Loader

运行阶段由 `loader.c` 编译生成，它是一段约 5296 字节的位置无关代码。

**核心流程：**

1. **解析 llbin 头部**：从传入的 llbin 指针读取 128 字节头部，获取各表的偏移和大小。
2. **内存映射**：使用 `mmap` 系统调用分配一块足够大的内存区域，将 llbin 中的 image 数据按照段信息映射到正确的偏移位置。每个段设置相应的内存权限（R/W/X）。
3. **基址重定位**：遍历 fixup 表，将每个条目指向的位置加上实际加载基址与预期基址的差值。
4. **符号导入**：遍历 import 表，对每个需要导入的符号：
   - 使用 `link_map` 链表或 `/proc/self/maps` 找到目标库的基址。
   - 在目标库的符号表中使用 GNU hash 或 SysV hash 查找符号地址。
   - 将找到的地址填入 GOT 对应位置。
5. **IFUNC 解析**：对每个 IRELATIVE 类型的重定位，调用 resolver 函数获取最终地址，填入目标位置。
6. **初始化**：遍历 init 表，按顺序调用每个构造函数。
7. **调用导出函数**：根据传入的函数哈希值，在 export 表中查找匹配的函数，调用它并返回结果。

### 为什么选择这种拆分

这种两阶段设计的核心权衡在于：**将复杂性放在有更多自由度的环境中处理。**

Python 运行在开发者的机器上，可以使用任何库、没有任何体积限制、不需要位置无关、有完整的调试工具。Loader 运行在被注入的目标进程中，受到上述所有约束。通过在 Python 中完成 ELF 解析，loader 的职责被简化为"读取 llbin 格式、执行固定操作"——一个纯粹的机械执行过程，不涉及任何格式解析的决策逻辑。

这种分离还带来了一个额外的好处：**跨运行时兼容性**。由于 loader 不需要直接解析 ELF，它不会受到不同 libc 实现中 ELF 细节差异的影响。所有与 ELF 格式相关的兼容性问题都在 Python 端处理，loader 只关心 llbin 这一种格式。

---

## Shellcode 组成部分详解

SREI 最终输出的 shellcode 由四个部分拼接而成：

```
Shellcode = Bootstrap(68B) + Loader(5296B) + llbin + UserData
```

### Bootstrap（引导代码，68 字节）

Bootstrap 是一段手工编写的 x86_64 机器码，位于 shellcode 的最前端。它的职责是：获取自身在内存中的地址，计算出后续各组件的偏移，设置好调用约定所需的寄存器，然后跳转到 Loader。

**工作原理：**

1. **获取当前地址**：使用经典的 `call $+5 / pop rax` 技巧。`call $+5` 将下一条指令的地址压入栈中，`pop rax` 将其弹出到 `rax` 寄存器。此时 `rax` 中保存的就是这段代码在内存中的实际运行地址，无论 shellcode 被加载到哪个地址都能正确获取。

2. **计算偏移**：Bootstrap 知道自身大小（68 字节），也知道 Loader 紧随其后。通过 `rax + 68` 得到 Loader 的起始地址，通过 `rax + 68 + 5296` 得到 llbin 的起始地址。llbin 的长度存储在 llbin 头部中，紧随 llbin 之后的就是 UserData。

3. **设置寄存器**：按照 System V AMD64 调用约定，将参数放入正确的寄存器：
   - `rdi`：llbin 数据指针
   - `rsi`：llbin 数据长度
   - `rdx`：要调用的导出函数的哈希值
   - `rcx`：UserData 指针
   - `r8`：UserData 长度
   - `r9`：`dlsym` 函数指针（如果宿主进程提供的话），或者 `NULL`
   - `[rsp]`（栈顶）：标志位

4. **对齐栈**：System V AMD64 ABI 要求在执行 `call` 指令时，栈指针 `rsp` 必须是 16 字节对齐的。Bootstrap 通过 `and rsp, -16` 确保栈对齐。

5. **跳转到 Loader**：使用相对 `call` 指令跳转到 Loader 的起始位置。由于 Loader 紧随 Bootstrap 之后，这个相对偏移在编译时就是已知的。

Bootstrap 的 68 字节体积经过精心优化，每一字节都有明确的用途。它不依赖任何外部地址，所有计算都基于相对偏移，完全满足位置无关的要求。

### Loader（加载器，5296 字节）

Loader 是 SREI 的核心组件，使用 C 语言编写（`loader.c`），通过特殊的编译选项生成：

```
gcc -Os -fPIC -ffreestanding -nostdlib -fno-stack-protector loader.c -o loader.o
objcopy -O binary -R .note -R .comment loader.o loader.bin
```

**编译选项说明：**

- `-Os`：优化代码体积（而非速度），因为 loader 对体积极其敏感。
- `-fPIC`：生成位置无关代码，所有地址访问都通过 RIP 相对寻址或 GOT 间接寻址。
- `-ffreestanding`：不假设标准库的存在，编译器不会生成对 `memcpy`、`memset` 等函数的隐式调用。
- `-nostdlib`：不链接标准库和启动文件，入口点由我们自己定义。
- `-fno-stack-protector`：禁用栈保护（stack canary），因为 loader 没有环境支持它。

编译后，通过 `objcopy` 将 `.text` 段提取为原始字节序列，存储在 `loader_bytes.py` 中供 Python 打包器使用。

Loader 的内部实现不调用任何 libc 函数。所有系统调用（`mmap`、`mprotect`、`write` 等）通过内联 `syscall` 指令直接发起。内存操作（拷贝、清零）使用手写的循环实现。符号查找则通过直接操作 `link_map` 链表或解析 `/proc/self/maps` 来完成。

### llbin（中间格式）

llbin 是 SREI 定义的中间格式，用于在 Python packer 和 C loader 之间传递数据。它的结构如下：

```
llbin = Header(128B) + Image + FixupTable + ImportTable + SegmentTable + InitTable + ExportTable
```

**头部（128 字节）：** 包含一个 8 字节的 magic number（用于校验）、llbin 格式版本号、image 大小、各表的偏移和大小、预期的加载基址、TLS 相关参数等。头部的大小固定为 128 字节，所有字段使用固定偏移，loader 可以直接通过偏移量访问，不需要解析逻辑。

**Image：** 从原始 ELF 中提取的所有 `PT_LOAD` 段数据，按照它们在虚拟地址空间中的布局拼接而成。Image 中已经包含了代码、数据、GOT 等内容，但所有需要重定位的位置尚未修复。

**Fixup 表：** 所有 `R_X86_64_RELATIVE` 类型的重定位条目。每个条目记录一个偏移量，指向 image 中需要加上加载基址的位置。这是最简单的重定位类型，也是数量最多的一种。

**Import 表：** 所有需要从外部库导入的符号。每个条目记录：符号名（以哈希形式存储）、所属库名（以索引形式指向依赖库列表）、以及需要填入的 GOT 位置偏移。Loader 需要找到目标库、在其中查找符号、将地址写入指定位置。

**Segment 表：** 记录各内存段的虚拟地址偏移、大小和权限标志。Loader 在执行 `mmap` 时需要这些信息来正确设置内存布局和页权限。

**Init 表：** 构造函数指针数组。这些是原始 ELF 中 `DT_INIT_ARRAY` 的内容，已经转换为相对于 image 基址的偏移。Loader 在完成所有重定位后，按顺序调用这些函数。

**Export 表：** 本库导出的所有符号。每个条目记录符号名的哈希和对应的偏移地址。Loader 通过匹配哈希值来查找用户指定的导出函数。

llbin 格式的设计原则是：**所有在 Python 端能做的决策都已做出，loader 只需要机械地执行**。没有需要 loader 动态判断的条件分支（除了符号查找路径的选择），没有需要解析的复杂格式，所有数据都按照固定结构排列。

### UserData（用户数据）

UserData 是一段任意的字节序列，附加在 shellcode 的末尾。它的内容完全由用户定义，会被原样传递给最终调用的导出函数。

UserData 的典型用途包括：配置信息、命令字符串、加密密钥等。通过将数据嵌入 shellcode 本身，避免了额外的数据传输和内存分配。

---

## 与 sRDI 的对比

下面从多个维度对 SREI 和 sRDI 进行详细对比：

| 方面 | sRDI | SREI |
|------|------|------|
| 目标格式 | PE DLL | ELF .so |
| 运行时解析 | Loader 解析 PE 头 | Python 预处理为 llbin |
| Loader 大小 | ~8KB | 5296B |
| 符号查找 | PEB → InLoadOrderModuleList | link_map + /proc/self/maps 双路径 |
| Hash 查找 | NamePointerTable 二分查找 | GNU hash (含 bloom filter) / SysV hash |
| IFUNC | 无（PE 没有 IFUNC 概念） | STT_GNU_IFUNC + IRELATIVE |
| 构造函数 | DllMain（单个入口） | init_array（多个入口） |
| TLS | 无 | PT_TLS + 自定义 __tls_get_addr |
| C++ 异常 | 无 | .eh_frame + __register_frame |
| 自解析 | 遍历 PEB（始终可用） | link_map（glibc/Android）或 /proc/self/maps（musl） |
| C 运行时兼容 | 仅 Windows | glibc 2.17+ / musl / Bionic |

### 最大的架构差异之一：自解析数据源

sRDI 和 SREI 都面临一个共同的问题：如何在运行时找到已经加载的共享库，以便解析导入符号？但两者可用的数据源有着本质的区别。

**sRDI 使用 PEB（Process Environment Block）。** PEB 是 Windows 内核为每个进程维护的数据结构，始终映射到用户空间，可以通过 `gs:[0x60]`（x64）直接读取。PEB 中包含 `InLoadOrderModuleList`，这是一个双向链表，记录了进程中所有已加载模块的基地址和名称。PEB 始终可用，不依赖于任何运行时库的支持，这使得 sRDI 的符号查找路径完全自包含。

**SREI 使用 link_map + /proc/self/maps 双路径。** `link_map` 是 glibc 的 `rtld`（runtime linker/loader）维护的一个链表，记录了已加载共享库的信息。`link_map` 可以通过 `_GLOBAL_OFFSET_TABLE_[2]`（即 `GOT[2]`，`_dl_runtime_resolve` 的调用会将 `link_map` 指针保存在此）间接获取。但 `link_map` 并不是 Linux 内核的机制，它是 glibc 的实现细节。在其他 libc 实现（如 musl）中，`link_map` 可能不存在或者结构不同。

为此，SREI 实现了回退路径：当 `link_map` 不可用时，转而解析 `/proc/self/maps`。这个文件由 Linux 内核维护，列出了进程的所有内存映射区域，包括文件名和地址范围。通过解析这个文件，loader 可以找到目标库的基址，然后自行解析 ELF 头部来查找符号。

这种双路径设计确保了 SREI 在 glibc（使用 `link_map`）、musl（使用 `/proc/self/maps`）和 Bionic（Android，使用 `link_map`）上都能正常工作，但代价是增加了 loader 的体积和复杂性。

### 最大的架构差异之二：预处理与运行时解析

sRDI 选择在运行时解析 PE 格式，而 SREI 选择在打包时预处理 ELF 格式。这个差异源于 PE 和 ELF 格式本身复杂度的不同。

**PE 格式相对简单。** PE 的重定位只有一种基址重定位类型（`IMAGE_REL_BASED_DIR64`），导入表的结构固定且直观，导出表通过 `NamePointerTable` 支持二分查找。整个 PE 加载流程可以用几百行 C 代码实现，体积控制在 8KB 以内是可行的。

**ELF 格式的多样性远超 PE。** 如前文所述，ELF 有 REL/RELA/JMPREL 三张重定位表，x86_64 上有数十种重定位类型，符号查找支持 GNU hash（含 bloom filter）和 SysV hash 两种算法，还有 IFUNC、init_array、TLS 等概念是 PE 所不具备的。如果要在运行时完整处理这些情况，loader 的体积将难以控制。

更关键的是，ELF 的某些行为依赖于 libc 实现。例如，符号版本解析在 glibc 和 musl 中的行为不同，TLS 的分配方式在不同线程库中也有差异。如果 loader 尝试在运行时处理这些差异，兼容性测试的负担将极其沉重。

**预处理的策略完美地规避了这些问题。** Python 有 `pyelftools` 这样的完整解析库，可以处理所有 ELF 特有的复杂性。打包时完成的工作包括：将三类重定位表合并为统一的 fixup/import 表、预计算符号哈希、提取并格式化所有元数据。运行时 loader 只需要处理一个简化的、经过验证的 llbin 格式——它不需要知道 ELF 是什么，不需要关心 libc 的差异，只需要执行固定的几步操作。

这个权衡带来的好处是多方面的：

1. **更小的 loader**：5296 字节 vs sRDI 的 ~8KB，尽管 ELF 比 PE 复杂得多。
2. **更好的跨运行时兼容性**：loader 不直接解析 ELF，避免了不同 libc 实现之间的差异。
3. **更可预测的运行时行为**：所有决策在打包时已经做出，运行时路径是确定的。
4. **更易于测试和验证**：Python 端的解析逻辑可以独立测试，不依赖注入环境。

---

## 可转换的 ELF 类型

SREI 并不能将所有 ELF 文件转换为 shellcode。位置无关性（Position Independent Code）是核心的前提条件——shellcode 可能被加载到任意地址，如果代码中包含硬编码的绝对地址，它将无法正确执行。

下表列出了各种 ELF 类型与 SREI 的兼容性：

| ELF 类型 | ET 类型 | PIC | 重定位 | 导出 | 结果 | 原因 |
|----------|---------|-----|--------|------|------|------|
| .so (gcc -shared -fPIC) | ET_DYN | 是 | 有 | 有 | 完全支持 | 标准共享库，SREI 主要目标 |
| PIE exe + 导出函数 | ET_DYN | 是 | 有 | 有 | 完全支持 | 等同于 .so |
| PIE exe 无导出 | ET_DYN | 是 | 有 | 无 | 需手动处理 | 构造函数可执行，但无法自动调用入口 |
| non-PIE exe | ET_EXEC | 否 | 无 | 无 | 不支持 | 地址硬编码为 0x400000+ |
| 静态链接 exe | ET_EXEC | 否 | 无 | 无 | 不支持 | 无 PT_DYNAMIC，无重定位 |
| Go 静态 exe | ET_EXEC | 否 | 无 | 无 | 不支持 | 59MB+，地址全部固定 |

**核心条件可以总结为：PIC/PIE + 重定位信息 + 导出函数 = 可转换为 shellcode。**

具体来说，一个 ELF 文件满足以下三个条件就可以被 SREI 转换：

1. **位置无关代码（PIC）**：文件类型为 `ET_DYN`（包括 `.so` 和 PIE 可执行文件），所有代码和数据访问都通过相对寻址或 GOT 间接寻址实现，不包含硬编码的绝对地址。

2. **包含重定位信息**：文件中有 `PT_DYNAMIC` 段，包含 `DT_RELA` / `DT_REL` / `DT_JMPREL` 等重定位表。这些信息告诉 loader 哪些位置需要在加载时修复。

3. **导出了至少一个函数**：`.dynsym` 中存在 `st_shndx != SHN_UNDEF` 且类型为 `STT_FUNC` 的符号。SREI 需要一个导出函数作为 shellcode 执行的入口点。

**关于 Rust cdylib**：Rust 的 `crate-type = ["cdylib"]` 产出的 `.so` 文件完全满足上述三个条件。它使用 `-fPIC` 编译，包含完整的重定位信息，并且通过 `#[no_mangle] pub extern "C" fn` 导出 C 兼容的函数。Rust cdylib 的体积通常很小（相比 Go），没有运行时 GC，非常适合作为 SREI 的目标。

**与 sRDI 的一致性**：sRDI 同样只转换 `.dll`（位置无关的动态链接库），不转换 `.exe`（地址硬编码的可执行文件）。这一点上两个工具的设计哲学是一致的——只有位置无关的动态库才是合理的 shellcode 化目标。

---

## 已知限制与未来方向

### 符号版本控制（Symbol Versioning）

glibc 使用符号版本控制（`DT_VERNEED` / `DT_VERSYM`）来实现向后兼容。同一个符号名（如 `memcpy`）可能存在多个版本（如 `GLIBC_2.2.5` 和 `GLIBC_2.14`），不同版本的语义可能略有差异。

SREI 目前忽略符号版本，仅按名称匹配。这在大多数情况下是可以工作的，因为同一个 libc 中通常只有一个版本的给定符号。但在跨版本场景下可能出问题：例如，目标进程加载的是 glibc 2.17，而 `.so` 在编译时绑定的是 glibc 2.31 版本的某个符号。如果该符号在两个版本之间的行为发生了变化，SREI 的名称匹配可能找到错误的版本。

在实际测试中，SREI 已经验证了以下高复杂度库的兼容性：

- **libcrypto**（OpenSSL 密码学库）：8646 个重定位条目，大量使用 IFUNC（`x86_64` AES-NI 优化等），无符号版本冲突。
- **libcurl**（HTTP 客户端库）：依赖多个子系统库，符号数量多但无版本冲突。
- **libsqlite3**（嵌入式数据库）：大量使用全局变量和回调函数，重定位类型多样，无版本冲突。

目前的测试结果表明，在典型使用场景中，符号版本忽略策略是实用的。但如果你在跨大版本 glibc 的环境中使用 SREI，需要注意这一限制。

### TLS 多线程支持

TLS（Thread Local Storage）的多线程支持受到 `pthread_key` 可用性的限制。问题的根源在于：

当宿主进程没有链接 `libpthread`（即不是多线程程序），并且 glibc 版本低于 2.34（2.34 将 `libpthread` 合入了 libc）时，SREI 的 TLS 实现会退化为单线程回退模式。在这个模式下：

- 所有线程共享同一个 TLS 块。
- 多个线程并发访问 `__thread` 变量会导致数据竞争（data race）。
- `__tls_get_addr` 的自定义实现无法正确区分不同线程的 TLS 存储。

不过在典型的 shellcode 使用场景中，这个限制通常不构成实际问题。Shellcode 的执行模式通常是：单次执行、短生命周期、不需要持久化 TLS 状态。在这些场景下，单线程 TLS 回退模式完全可以胜任。

如果未来的使用场景需要完整的 TLS 多线程支持，可能的解决方向包括：通过 `clone` 系统调用自行管理 TLS 存储、利用 `arch_prctl` 系统调用设置线程区域指针、或者在注入前确认宿主进程的 TLS 基础设施可用性。
