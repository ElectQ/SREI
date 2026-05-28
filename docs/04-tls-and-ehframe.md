# TLS 线程本地存储与 C++ 异常处理

本文档面向需要在反射加载场景中支持 TLS 变量或 C++ 异常处理的开发者，详细阐述 SREI 如何在绕过 ld.so 的前提下实现这两项运行时机制。

## PE-ELF 特性对照表

| Windows/PE | Linux/ELF | 说明 |
|---|---|---|
| IMAGE_TLS_DIRECTORY | PT_TLS 段 | TLS 描述 |
| TlsAlloc / TlsGetValue | \_\_tls_get_addr + tls_index | TLS 访问机制 |
| \_\_declspec(thread) | \_\_thread / thread_local | TLS 变量声明 |
| .pdata (RUNTIME_FUNCTION) | .eh_frame (DWARF CFI) | 异常展开信息 |
| RtlAddFunctionTable | \_\_register_frame | 注册展开信息 |
| \_\_C_specific_handler | \_Unwind_RaiseException | 异常处理机制 |

## Part 1: TLS (Thread-Local Storage)

### 什么是 TLS

当 .so 中使用 `__thread` 变量或 C++ 的 `thread_local` 时，编译器会生成特殊的重定位类型。对于 x86_64 架构，常见的 TLS 重定位包括：

- `R_X86_64_DTPMOD64`：请求加载模块的模块 ID
- `R_X86_64_DTPOFF64`：TLS 变量在模块 TLS 块内的偏移
- `R_X86_64_TPOFF64`：TLS 变量相对于线程指针（%fs 基址）的直接偏移

运行时，`__tls_get_addr` 函数根据模块 ID 和偏移量计算 TLS 变量的实际地址。编译器生成的代码通过 GOT 间接调用 `__tls_get_addr`，传入一个 `tls_index` 结构体，该结构体包含两个字段：`ti_module`（模块 ID）和 `ti_offset`（块内偏移）。对于 General Dynamic (GD) 模型的 TLS 访问，编译器生成的典型代码序列为：

```asm
lea    rdi, [rip + tls_var@TLSGD]
call   __tls_get_addr@PLT
; rax = tls_var 的地址
```

### 标准 TLS 模型

在正常加载的 .so 中，glibc 的动态链接器 (ld.so) 管理 TLS 的完整生命周期：

1. 为每个包含 PT_TLS 段的库分配唯一的模块 ID
2. 在 `__tls_get_addr` 中管理每个线程的 TLS 块
3. 每个线程的 TLS 区域包含所有已加载模块的 TLS 副本

标准流程如下：新线程创建时，glibc 为该线程分配所有已知模块的 TLS 空间；新库通过 `dlopen` 加载时，glibc 在内部数据结构中注册新的 TLS 模块，并延迟分配新模块的线程空间（在首次 `__tls_get_addr` 调用时按需分配）。

**核心问题**：SREI 的 loader 不是 ld.so —— 它没有权限修改 glibc 的 TLS 模块注册表。glibc 的 TLS 子系统通过内部数据结构（`_dl_tls_dtv`、`_dl_tls_static_used` 等）管理模块，这些数据结构不对外部代码开放。直接操作可能导致内存损坏或段错误。

### SREI 的 TLS 实现方案

SREI 通过自定义 `__tls_get_addr` 与 TPOFF 直接映射相结合的方式绕过上述限制。整个方案分为提取、分配、访问三个阶段。

#### 1. TLS 镜像提取 (packer 端)

Packer 在处理 ELF 输入时，遍历所有程序头查找 `PT_TLS`（类型值 7）段。对于找到的 PT_TLS 段，提取以下元数据：

- `tls_init_off`：初始化映像（.tdata）在 image 中的偏移，计算为 `p_vaddr - base_vmaddr`
- `tls_init_size`：初始化映像大小（`p_filesz`），即 .tdata 段的大小
- `tls_total_size`：TLS 总大小（`p_memsz`），包含 .tdata + .tbss
- `tls_align`：TLS 对齐要求（`p_align`）

由于 PT_TLS 段通常与某个 PT_LOAD 段重叠（.tdata 位于可读写段内），初始化数据已经包含在打包后的 image 中。Packer 只需记录偏移和尺寸元数据到 llbin 头部的对应字段：

```c
struct llbin_header {
    ...
    uint32_t tls_init_off;
    uint32_t tls_init_size;
    uint32_t tls_total_size;
    uint32_t tls_align;
};
```

#### 2. TLS 块分配 (loader 端)

Loader 在处理重定位之前检测 `hdr->tls_total_size > 0`，执行 TLS 初始化：

- 通过 dlsym 或 self-resolve 查找 `pthread_key_create`、`pthread_getspecific`、`pthread_setspecific`
- 如果 `pthread_key_create` 可用，创建一个 pthread key 用于多线程 TLS 存储，设置 `srei_tls_key_init = 1`
- 将 `srei_tls_init_img` 指向 `base + hdr->tls_init_off`（image 中的 .tdata 位置）
- 记录 `srei_tls_init_sz` 和 `srei_tls_total_sz` 到静态变量

TLS 块的实际分配延迟到首次 `__tls_get_addr` 调用时执行（惰性分配）。`srei_tls_get_addr` 通过 `sys_mmap` 分配 `srei_tls_total_sz` 字节的内存，复制初始化映像到新块，并将剩余部分（.tbss 区域）清零。

#### 3. 自定义 \_\_tls_get_addr

在处理 IMPORT 类型 fixup 时，loader 检测到符号名 `__tls_get_addr` 后执行替换：

- 保存原始 `__tls_get_addr` 函数指针到 `srei_tls_real_fn`
- 将 GOT 中的 `__tls_get_addr` 指针替换为 `srei_tls_get_addr`

自定义的 `srei_tls_get_addr` 接收 `unsigned long *ti` 参数（对应 `tls_index` 结构）：

```c
static void *srei_tls_get_addr(unsigned long *ti)
{
    if (ti[0] != SREI_TLS_SENTINEL) {
        if (srei_tls_real_fn)
            return srei_tls_real_fn(ti);
        return (void *)0;
    }

    void *block = (void *)0;
    if (srei_tls_key_init)
        block = srei_tls_getspecific_fn(srei_tls_key);
    else if (srei_tls_fallback_block)
        block = srei_tls_fallback_block;

    if (!block) {
        block = mmap_alloc(srei_tls_total_sz);
        memcpy(block, srei_tls_init_img, srei_tls_init_sz);
        zero_fill(block + srei_tls_init_sz, remainder);
        if (srei_tls_key_init)
            srei_tls_setspecific_fn(srei_tls_key, block);
        else
            srei_tls_fallback_block = block;
    }

    return (void *)((uintptr_t)block + (uintptr_t)ti[1]);
}
```

`SREI_TLS_SENTINEL`（值为 `0xFFFE`）作为特殊标记，取代标准模型中的模块 ID。由于 SREI 只加载一个包含 TLS 的模块，不需要真正的模块 ID 分配机制。`srei_tls_get_addr` 通过哨兵值区分：是自己处理的请求还是应该转发给 glibc 原始函数的请求。这保证了宿主进程原有的 TLS 访问完全不受影响。

#### 4. 双模式存储

SREI 的 TLS 块存储有两种模式，自动根据运行环境选择：

**pthread_key 模式（多线程）**

当宿主进程链接了 libpthread（或 glibc >= 2.34，libpthread 合并入 libc）时，`pthread_key_create` 可用。Loader 创建 pthread key，每个线程通过 `pthread_getspecific` / `pthread_setspecific` 获取和设置各自的 TLS 块。

流程为：`srei_tls_get_addr` 被调用时，先通过 `pthread_getspecific(srei_tls_key)` 获取当前线程的 TLS 块；如果不存在，通过 `sys_mmap` 分配新块并复制初始化映像，然后通过 `pthread_setspecific` 绑定到当前线程；最后返回 `block + offset`。

**fallback_block 模式（单线程）**

当 `pthread_key_create` 不可用（宿主未链接 libpthread 且 glibc < 2.34）时，TLS 自动降级为单线程模式。使用静态全局指针 `srei_tls_fallback_block` 存储 TLS 块，所有线程共享同一个 TLS 块，没有线程隔离。

#### 5. TLS 重定位处理

Packer 识别两种 TLS 重定位类型并生成对应的 fixup：

**LLBIN_FIXUP_TLS_MODULE**

对应 `R_X86_64_DTPMOD64`（x86_64）、`R_AARCH64_TLS_DTPMOD64`（ARM64）、`R_386_TLS_DTPMOD32`（x86）、`R_ARM_TLS_DTPMOD32`（ARM）等重定位类型。在标准模型中，这类重定位要求填入模块 ID。

Loader 处理时将 GOT 槽位设置为哨兵值 `SREI_TLS_SENTINEL`（0xFFFE），这样运行时 `srei_tls_get_addr` 通过 `ti[0]` 即可识别出这是 SREI 模块的 TLS 请求：

```c
} else if (f->type == LLBIN_FIXUP_TLS_MODULE) {
    *slot = (uint64_t)SREI_TLS_SENTINEL;
}
```

**LLBIN_FIXUP_TLS_OFFSET**

对应 `R_X86_64_DTPOFF64`、`R_X86_64_TPOFF64`（x86_64）等重定位类型。Loader 处理分两种路径：

1. **TPOFF 路径（直接访问）**：通过 `srei_find_tls_slot()` 在当前线程的 TLS 区域（%fs 寄存器指向的内存）中搜索空闲槽位。从 `%fs - 8` 开始向下扫描，找到第一个零值 qword 即为可用偏移。找到后，将 TLS 初始化数据直接写入该位置，GOT 槽位设置为 `tpoff + addend`。后续访问通过 `%fs:offset` 直接完成，无需调用 `__tls_get_addr`。

2. **DTPOFF 路径（间接访问）**：GOT 槽位设置为 addend 值，运行时通过 `srei_tls_get_addr` 间接访问 TLS 变量。

TPOFF 路径下还需处理新线程的 TLS 初始化。Loader 通过 hook `pthread_create` 实现：当 `pthread_create` 被 fixup 解析到时，保存原始函数指针到 `srei_real_pthread_create`，将 GOT 槽位替换为 `srei_pthread_create_hook`。hook 函数分配一页临时内存保存原始参数（start_routine 和 arg），将自定义的 `srei_thread_wrapper` 作为新线程入口传给真实的 `pthread_create`。wrapper 在新线程启动时，通过 `sys_arch_prctl(ARCH_GET_FS)` 获取线程的 %fs 值，将初始化映像复制到 `fs + tpoff` 位置，然后释放临时内存并调用原始的 start_routine。

### TLS 静态变量

Loader 使用以下静态变量维护 TLS 状态。这些变量由 `linker.ld` 合并到 `.data` 输出段（`.data` + `.bss` 合并，保证可写），在 bootstrap 阶段其 RELATIVE 重定位被自动处理，因此在后续调用中持久有效：

```c
static srei_tls_get_addr_fn srei_tls_real_fn;               // 原始 __tls_get_addr
static srei_pthread_getspecific_fn srei_tls_getspecific_fn;  // pthread_getspecific
static srei_pthread_setspecific_fn srei_tls_setspecific_fn;  // pthread_setspecific
static srei_pthread_key_t srei_tls_key;                      // pthread key
static int srei_tls_key_init;                                // key 是否已初始化
static const uint8_t *srei_tls_init_img;                     // TLS 初始化映像指针
static uint32_t srei_tls_init_sz;                            // 初始化映像大小
static uint32_t srei_tls_total_sz;                           // TLS 总大小
static void *srei_tls_fallback_block;                        // fallback TLS 块
static int64_t srei_tls_tpoff;                               // TPOFF 偏移量
static srei_pthread_create_fn srei_real_pthread_create;      // 原始 pthread_create
```

`linker.ld` 的关键设计是将 `.data`、`.data.*`、`.bss`、`.bss.*`、`COMMON` 全部合并到 `.data` 输出段中：

```
.data : {
    *(.data)
    *(.data.*)
    *(.bss)
    *(.bss.*)
    *(COMMON)
}
```

这意味着所有静态变量都在同一可读写段内，bootstrap 加载器只需处理该段的 RELATIVE 重定位即可修正所有指针值。

### TLS 多线程限制

当宿主进程未链接 libpthread 且 glibc < 2.34 时：

- TLS 降级为单线程 fallback 模式
- 所有线程共享同一个 TLS 块
- 并发的 `__thread` 变量访问会导致数据竞争（data race）
- 在 shellcode 场景中通常可以接受：执行时间短、生命周期有限、多数情况下单线程执行

即使在 pthread_key 可用的多线程模式下，SREI 模块的 TLS 变量与宿主进程的 TLS 变量也完全隔离，无法通过标准机制互相访问。

## Part 2: C++ 异常处理 (.eh_frame)

### 什么是 .eh_frame

当 .so 包含 C++ 代码（例如链接了 libstdc++）时，`throw`/`catch` 异常处理需要栈展开（stack unwinding）信息。这些信息存储在 ELF 文件的 `.eh_frame` 段中，使用 DWARF Call Frame Information (CFI) 格式编码。

`.eh_frame` 段包含两类记录：

- **CIE (Common Information Entry)**：共享的前导信息，包括代码指针编码方式、数据对齐因子、返回地址寄存器编号等
- **FDE (Frame Description Entry)**：每个函数对应一条，描述该函数内各 PC 位置的栈帧状态（寄存器保存位置、栈指针偏移等）

当 C++ 异常抛出时，运行时展开器（unwinder）执行以下步骤：

1. 查找当前 PC 对应的 FDE
2. 根据 CFI 指令计算各寄存器的保存位置
3. 逐帧展开调用栈，检查每一帧是否有匹配的 catch 子句
4. 找到匹配的 catch 后恢复寄存器状态并跳转到 catch 代码
5. 如果展开到栈底仍未找到匹配的 catch，调用 `std::terminate()`

在标准加载流程中，ld.so 加载 .so 时自动处理 `.eh_frame` 注册。`__register_frame` 函数将 CFI 数据注册到展开器的查找表中，使异常展开器能够根据 PC 值定位到正确的 FDE。

### SREI 的 .eh_frame 实现

#### 1. 提取 (packer 端)

Packer 的 `process_eh_frame_elf` 函数负责提取 `.eh_frame` 数据。具体步骤如下：

1. 读取 ELF 节头表 (section headers)，验证节头偏移和大小的合法性
2. 通过节头字符串表（`.shstrtab`，由 `e_shstrndx` 索引）匹配节名为 `.eh_frame` 的节
3. 检查该节是否设置了 `SHF_ALLOC` 标志（确保它在运行时被加载到内存）
4. 检查节大小是否非零
5. 计算偏移：`off = sh_addr - base_vmaddr`（相对于 image 基址的偏移）
6. 验证 `.eh_frame` 不超出 image 范围（`off + sh_size <= total_size`）
7. 将 `eh_frame_off` 和 `eh_frame_size` 记录到 llbin 头部

由于 `.eh_frame` 节位于某个 PT_LOAD 段内，其数据已经包含在打包后的 image 中。Packer 只需记录位置和大小，不需要额外提取或复制数据。只处理第一个匹配的 `.eh_frame` 节。

#### 2. 注册 (loader 端)

Loader 在完成重定位处理和内存保护设置之后、调用构造函数之前，执行 `.eh_frame` 注册。注册顺序至关重要：构造函数中的代码可能使用 C++ 异常（例如构造函数内部调用的函数可能 throw），因此 `.eh_frame` 必须在构造函数执行前就绪。

```c
if (hdr->eh_frame_size > 0) {
    srei_register_frame_fn reg_frame = NULL;
    if (dlsym_fn)
        reg_frame = (srei_register_frame_fn)dlsym_fn(
            LLBIN_RTLD_DEFAULT, "__register_frame");
    else
        reg_frame = (srei_register_frame_fn)srei_resolve(
            &resolver, "__register_frame");
    if (reg_frame)
        reg_frame((const void *)(base + hdr->eh_frame_off));
}
```

查找 `__register_frame` 的方式取决于运行模式：

- **dlsym 参数模式**：直接通过宿主注入的 `dlsym_fn` 查找，使用 `RTLD_DEFAULT`（地址 `0xFFFFFFFFFFFFFFFF`）作为句柄，在所有已加载库的全局符号表中搜索
- **self-resolve / shellcode 模式**：通过 loader 内置的 ELF 解析器（`srei_resolver`）在已加载的共享库（libgcc_s.so 等）中查找

找到后，将 `base + eh_frame_off`（即 `.eh_frame` 数据在加载后 image 中的实际地址）传递给 `__register_frame`。注册完成后，libgcc 的展开器将该地址范围内的 CFI 数据纳入查找表，后续异常处理即可正常工作。

#### 3. 实测验证

通过 libstdc++ 嵌套异常测试验证了 `.eh_frame` 注册的正确性。测试场景为 3 层嵌套的 `try`/`throw`/`catch`：

```cpp
void inner() {
    throw std::runtime_error("level 3");
}

void middle() {
    try { inner(); }
    catch (const std::exception& e) {
        throw std::runtime_error(std::string("level 2: ") + e.what());
    }
}

void outer() {
    try { middle(); }
    catch (const std::exception& e) {
        throw std::runtime_error(std::string("level 1: ") + e.what());
    }
}
```

测试结果表明，三种运行模式下均正确工作：

- **dlsym 参数模式**：通过宿主注入的 `dlsym` 函数查找 `__register_frame`
- **self-resolve 模式**：通过 loader 内置的 ELF 解析器自主查找
- **shellcode 模式**：完全无外部依赖，通过 syscall 和自主解析完成所有工作

嵌套异常测试确认了：异常展开器能够正确解析反射加载模块的调用栈，每一层的 catch 子句都能被正确匹配和执行，throw 后的栈展开过程不会损坏宿主进程的状态。

### .eh_frame 在反射加载中的特殊性

- **标准 dlopen**：ld.so 在加载 .so 时自动处理 `.eh_frame` 注册，开发者无需关心
- **反射加载**：必须显式注册 `.eh_frame`。未注册时，展开器找不到异常抛出位置对应的 FDE，无法展开调用栈，导致 `_Unwind_RaiseException` 调用失败，最终触发 `std::terminate()` 终止进程
- **纯 C 的 .so**：不需要 `.eh_frame`，即使存在也不影响功能，此特性对纯 C 代码完全透明
- **C++ 代码**：如果 .so 包含任何可能 throw 的代码（包括隐式使用 libstdc++ 的功能），`.eh_frame` 注册是必须的。即使代码中不直接使用 `throw`，libstdc++ 的内部实现（如 `std::string` 分配、`std::vector` 扩容等）也可能抛出 `std::bad_alloc` 异常
