# SREI — Shellcode Reflective ELF Injection

将 Linux 共享库（.so）转换为位置无关的 shellcode，用于内存中加载执行。

Linux 版 sRDI（Shellcode Reflective DLL Injection）。纯 Python 实现，无需编译。

## 架构概览

```
┌─────────────────────────────────────────────────────────────────┐
│                        SREI 转换流水线                           │
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │ ELF .so  │───>│  llpack  │───>│  .llbin  │───>│ shellcode│  │
│  │ (输入)   │    │ (Python) │    │ (中间格式)│    │ (输出)   │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│                                                                 │
│  Shellcode = Bootstrap(68B) + Loader(3.8KB) + llbin + UserData│
│                                                                 │
│  运行时:                                                        │
│  Bootstrap → 设置参数 → 调用 srei_load()                       │
│  srei_load → mmap 内存 → 加载镜像 → 修复重定位 → 调用构造函数  │
│           → 查找导出函数 → 调用并传入 user_data                 │
└─────────────────────────────────────────────────────────────────┘
```

### 运行时加载流程

```
Shellcode 被执行
    │
    ▼
Bootstrap (68 字节, x86_64)
    │  call $+5 / pop rax          获取当前地址
    │  lea rdi, [rax+offset]       计算各段偏移
    │  设置 SysV AMD64 调用参数
    │     rdi = llbin 数据指针
    │     rsi = llbin 数据长度
    │     rdx = 导出函数哈希
    │     rcx = user_data 指针
    │     r8  = user_data 长度
    │     r9  = NULL (触发自解析)
    │     [rsp] = flags
    │
    ▼
srei_load() — PIC Loader (3819 字节)
    │
    ├─ 1. 解析 llbin 头，校验 magic/version
    ├─ 2. [自解析] 双路径库发现:
    │     ├─ 快路径: /proc/self/auxv → AT_BASE → ld.so → _r_debug → link_map 链表
    │     │  (glibc/Android/Bionic, l_ld 直接给 dynamic section)
    │     └─ 回退:   /proc/self/maps 解析 (musl/Alpine/OpenWrt)
    │     → libc 优先交换到索引 0, ld-musl 也识别为 libc
    │     → GNU hash (含 bloom filter) + SysV hash 双支持
    │     → STT_GNU_IFUNC 自动调用 resolver
    ├─ 3. 三级 dlopen 查找 DT_NEEDED:
    │     libdl dlopen → __libc_dlopen_mode → linker dlopen (Android)
    ├─ 4. mmap 分配 RW 内存，8 字节 word memcpy
    ├─ 5. 遍历 fixup 表:
    │     ├─ REBASE:    *slot += slide
    │     ├─ IRELATIVE: 调用 IFUNC resolver，写入返回地址
    │     └─ IMPORT:    查找符号地址，写入 GOT
    │        ├─ dlsym 模式: dlsym(RTLD_DEFAULT, name)
    │        └─ 自解析模式: bloom filter → GNU/SysV hash 查找
    ├─ 6. __builtin___clear_cache 刷新指令缓存
    ├─ 7. mprotect RELRO 段为只读 + 应用段权限 (r/w/x)
    ├─ 8. 调用 init_array 构造函数
    ├─ 9. 按 ROTR13 哈希查找导出函数，传入 user_data 调用
    └─ 10. 可选: 擦除 llbin 头 / 擦除全部输入内存
    │
    ▼
返回加载基址
```

## 快速开始

### 安装

```bash
# 从源码安装 (开发模式)
make embed          # 编译 loader 并嵌入 Python
pip install -e . --user

# 验证
srei hash printf
# 0x0776fa5e  printf
```

### 命令行使用

```bash
# 将 .so 转换为 shellcode
srei pack payload.so -o shellcode.bin -f payload_run -u "hello"

# 指定输出格式
srei pack payload.so -o shellcode.c -f payload_run --format c
# 格式: raw (默认), string (\x..), c ({0x..}), python (b'...')

# 计算符号哈希
srei hash payload_run memcpy printf
# 0x95dde36b  payload_run
# 0x0d44b3b6  memcpy
# 0x0776fa5e  printf

# 查看文件信息
srei info payload.so        # ELF 文件
srei info payload.llbin     # llbin 中间文件
```

### Python API

```python
import srei

# 加载 .so 文件
so_bytes = open('payload.so', 'rb').read()

# 转换为 shellcode
func_hash = srei.hash_name('payload_run')
shellcode = srei.convert_to_shellcode(
    so_bytes,
    func_hash=func_hash,
    user_data=b'hello from python',
    flags=0  # srei.SREI_CLEARHEADER | srei.SREI_CLEARMEMORY
)

# 写入文件
open('shellcode.bin', 'wb').write(shellcode)
```

### C API (嵌入 loader)

```c
#include "llbin.h"

extern uintptr_t srei_load(
    const uint8_t *data, size_t data_len,
    uint32_t func_hash,
    const void *user_data, uint32_t user_data_len,
    void *(*dlsym_fn)(void *, const char *),
    uint32_t flags
);

// 方式 1: 使用 dlsym 解析符号
uintptr_t base = srei_load(data, len, hash, "msg", 3, dlsym, 0);

// 方式 2: 自解析模式 (无需 dlsym)
uintptr_t base = srei_load(data, len, hash, "msg", 3, NULL, 0);
```

### Shellcode 执行测试

```bash
# 编译测试 .so
gcc -Os -shared -fPIC -fuse-ld=gold -o payload.so payload.c

# 生成 shellcode
srei pack payload.so -o test.bin -f payload_run -u "hello"

# 执行
./bin/sc_test test.bin
```

## 编写可加载的 .so

```c
// payload.c — 示例
#include <stdio.h>

__attribute__((constructor))
void payload_init(void) {
    puts("[payload] constructor called");
}

// 导出函数签名: void func(const void *data, uint32_t len)
int payload_run(const char *msg, unsigned int len) {
    printf("[payload] run: \"%s\" (%u)\n", msg, len);
    return 42;
}
```

编译:
```bash
gcc -Os -shared -fPIC -fuse-ld=gold -o payload.so payload.c
```

**限制:** 自解析模式下，依赖库通过 dlopen 自动加载（支持 libz、libcrypto 等）。目前不支持 TLS 重定位（libpthread、`__thread` 变量）和 C++ 异常处理。

## 自解析模式

当 `dlsym_fn = NULL` 时，loader 进入自解析模式，通过双路径发现已加载库：

### 快路径: link_map (glibc / Android / Bionic)

1. 读取 `/proc/self/auxv`（~320 字节，栈上缓冲区）→ 获取 AT_BASE（ld.so 基址）
2. 解析 ld.so 的 ELF 头 → 在其符号表中查找 `_r_debug`
3. 读取 `_r_debug.r_map` → 遍历 `link_map` 链表
4. 每个 `link_map` 直接提供 `l_addr`（load_bias）和 `l_ld`（dynamic section 指针）
5. 同时从 ld.so 解析 `dlopen` 存入 `linker_dlopen`（用于 Android/Bionic）

### 回退路径: /proc/self/maps (musl / Alpine / OpenWrt)

当 link_map 失败（无 `_r_debug`，如 musl）时自动触发：

1. 读取 `/proc/self/maps`（8KB 栈上缓冲区）
2. 逐行解析，提取 .so 文件的基地址和路径
3. 对每个 .so 调用 `srei_parse_lib` 解析 ELF 头 → PT_DYNAMIC → hash 表

### 符号查找

- **Bloom filter** 加速 GNU hash 负查找（O(1) 排除不存在的符号）
- GNU hash / SysV hash 双支持（SysV 用于 musl 等无 GNU hash 的库）
- libc 优先搜索（匹配 `libc-*`、`libc.so*`、`ld-musl-*`）
- 自动检测 `STT_GNU_IFUNC` 符号并调用 resolver

### DT_NEEDED dlopen 三级查找

```
1. libdl.so dlopen         (glibc < 2.34)
2. __libc_dlopen_mode      (glibc ≥ 2.34, 加 __RTLD_DLOPEN 标志)
3. linker dlopen           (Android/Bionic, dlopen 在 linker64 中)
```

### DT_STRTAB 绝对/相对地址兼容

动态链接器在 glibc 上将 DT_STRTAB/DT_SYMTAB 改写为绝对地址，但在 musl 上保持相对地址。
`dyn_ptr()` 函数自动检测：若 `d_val >= load_bias` 则视为绝对地址，否则加上 load_bias。

## 兼容性

| 环境 | 自解析 | DT_NEEDED | 说明 |
|------|:------:|:---------:|------|
| **glibc 2.17-2.33** | ✅ | ✅ | link_map 快路径 + libdl dlopen |
| **glibc 2.34+** | ✅ | ✅ | link_map + `__libc_dlopen_mode` |
| **musl** (Alpine, OpenWrt) | ✅ | ⚠️ | /proc/self/maps 回退；dlopen 不可用 |
| **Android/Bionic** | ✅ | ✅ | link_map + linker dlopen |
| **无 /proc 容器** | ❌ | ❌ | 需调用者提供 dlsym_fn |

- **内核**: Linux 3.10+ (x86_64)
- **系统调用**: mmap/mprotect/munmap/open/read/close（x86_64 ABI 从未变过）
- **Loader 大小**: 3819 字节（含双路径自解析 + bloom filter + dlopen 回退）

## 项目结构

```
SREI/
├── loader/             # PIC loader (编译为 shellcode)
│   ├── loader.c        # 主加载逻辑 (word memcpy, 三级 dlopen)
│   ├── syscall.h       # x86_64 系统调用封装
│   ├── selfresolve.h   # 自解析: link_map + /proc/self/maps + bloom filter
│   ├── resolve.h       # ROTR13 哈希
│   └── linker.ld       # 链接脚本 (.text.entry 在最前)
├── packer/
│   ├── llpack.c        # C ELF→llbin 转换器
│   └── llbin.h         # llbin v3 格式定义 (104 字节头)
├── python/
│   ├── srei.py         # CLI + convert_to_shellcode() API
│   ├── llpack.py       # 纯 Python ELF→llbin 转换器
│   ├── lltool.py       # llbin 查看工具
│   └── loader_bytes.py # 嵌入的 loader 字节 (make embed 生成)
├── test/
│   ├── payload.c       # 测试用 .so
│   ├── test_zlib.c     # zlib DT_NEEDED 测试
│   ├── test_selfresolve.c  # 自解析测试
│   └── sc_test.c       # shellcode 执行测试
├── native/
│   └── native_loader.c # 原生 dlsym 加载器
├── setup.py            # pip install
└── Makefile
```

## llbin 中间格式

llbin v3 头部 (104 字节):

| 偏移 | 大小 | 字段 | 说明 |
|------|------|------|------|
| 0 | 4 | magic | `0x4E424C4C` ("LLBN") |
| 4 | 4 | version | 3 |
| 8 | 4 | arch | CPU 类型 |
| 12 | 4 | flags | 保留 |
| 16 | 8 | entry_off | 入口偏移 |
| 24 | 8 | image_size | ELF 镜像大小 |
| 32 | 8 | preferred_base | 首选基址 |
| 40 | 4 | image_off | 镜像数据偏移 |
| 44 | 4 | fixup_off | fixup 表偏移 |
| 48 | 4 | fixup_count | fixup 数量 |
| 52 | 4 | import_off | import 表偏移 |
| 56 | 4 | import_count | import 数量 |
| 60 | 4 | strings_off | 字符串表偏移 |
| 64 | 4 | strings_size | 字符串表大小 |
| 68 | 4 | seg_count | 段数量 |
| 72 | 4 | init_off | init 函数表偏移 |
| 76 | 4 | init_count | init 函数数量 |
| 80 | 4 | export_off | export 表偏移 |
| 84 | 4 | export_count | export 数量 |
| 88 | 4 | needed_off | DT_NEEDED 表偏移 |
| 92 | 4 | needed_count | DT_NEEDED 数量 |
| 96 | 4 | fini_off | fini 函数表偏移 |
| 100 | 4 | fini_count | fini 函数数量 |

Fixup 类型:
- `0` REBASE: `*slot += slide`
- `1` IMPORT: `*slot = resolve(import_name) + addend`
- `2` IRELATIVE: `*slot = ifunc_resolver(*slot + slide)()`

## 处理的重定位类型

| x86_64 | 类型 | 处理方式 |
|--------|------|----------|
| `R_X86_64_RELATIVE` (8) | REBASE | 加上 slide 偏移 |
| `R_X86_64_64` (1) | IMPORT | 按符号名查找 |
| `R_X86_64_GLOB_DAT` (6) | IMPORT | 按符号名查找 |
| `R_X86_64_JUMP_SLOT` (7) | IMPORT | 按符号名查找 |
| `R_X86_64_IRELATIVE` (37) | IRELATIVE | 调用 IFUNC resolver |

## 编译依赖

- GCC (x86_64)
- ld.gold (ld.bfd 可能丢弃 init_array 条目)
- objcopy
- Python 3.6+

```bash
make          # 编译所有
make test     # 运行测试
make embed    # 重新嵌入 loader 字节
make clean    # 清理
```

## TODO

- [ ] **i386 支持** — 32 位 syscall 封装 + bootstrap + linker.ld
- [ ] **aarch64 支持** — arm64 syscall + bootstrap
- [x] **dlopen 回退层** — 三级查找: libdl → `__libc_dlopen_mode` → linker dlopen
- [x] **双路径自解析** — link_map 快路径 (glibc/Android) + /proc/self/maps 回退 (musl)
- [x] **Bloom filter** — GNU hash 负查找 O(1) 排除
- [x] **musl 兼容** — DT_HASH 回退 + ld-musl 识别 + libc_idx=0 循环修复
- [x] **PT_GNU_RELRO** — 重定位后将 GOT 等区域 mprotect 为只读
- [x] **DT_FINI/DT_FINI_ARRAY** — 析构函数提取和存储
- [ ] **符号版本 (DT_VERNEED/DT_VERSYM)** — 处理 GLIBC_2.x 版本标记
- [ ] **C++ .eh_frame** — 异常处理/栈展开
- [ ] **TLS (PT_TLS)** — `__thread` 变量支持
- [ ] **导入混淆** — sRDI 的 Fisher-Yates 随机化 + 延迟加载

## 致谢

灵感来自 [sRDI](https://github.com/monoxgas/sRDI) (Shellcode Reflective DLL Injection)。

## 许可证

MIT
