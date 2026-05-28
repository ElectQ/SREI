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
│  Shellcode = Bootstrap(68B) + Loader(5560B) + llbin + UserData│
│                                                                 │
│  运行时:                                                        │
│  Bootstrap → 设置参数 → 调用 srei_load()                       │
│  srei_load → mmap 内存 → 加载镜像 → 修复重定位 → TLS 初始化    │
│           → eh_frame 注册 → 调用构造函数                       │
│           → 查找导出函数 → 调用并传入 user_data                 │
└─────────────────────────────────────────────────────────────────┘
```

详细设计见 [docs/](docs/) 目录下的技术文档：
- [设计理念与架构概览](docs/01-design-philosophy.md)
- [ELF 关键结构与 llbin 预处理](docs/02-elf-structures-and-llbin.md)
- [Loader 内部机制](docs/03-loader-internals.md)
- [TLS 线程本地存储与 C++ 异常处理](docs/04-tls-and-ehframe.md)

## 快速开始

无需安装，克隆后直接使用（需要 Python 3.6+）：

```bash
# 将 .so 转换为 shellcode
python3 python/srei.py pack payload.so -o shellcode.bin -f worker -u "hello"

# 指定输出格式: raw (默认), string, c, python
python3 python/srei.py pack payload.so -o shellcode.c -f worker --format c

# 计算符号哈希
python3 python/srei.py hash printf worker
# 0x0776fa5e  printf
# 0x679f22de  worker

# 查看文件信息
python3 python/srei.py info payload.so
```

## 编写可加载的 .so

导出函数签名: `int func(const void *data, uint32_t len)`

```c
#include <stdio.h>
int worker(const char *msg, unsigned int len) {
    printf("[payload] run: \"%.*s\" (%u)\n", len, msg, len);
    return 42;
}
```

```bash
gcc -Os -shared -fPIC -o payload.so payload.c
```

Rust (`cargo new --lib payload && cd payload`):

```toml
# Cargo.toml
[lib]
crate-type = ["cdylib"]
```

```rust
// src/lib.rs
#[no_mangle]
pub extern "C" fn worker(data: *const u8, len: u32) -> i32 {
    eprintln!("[rust] hello from shellcode!");
    0
}
```

```bash
cargo build --release
# target/release/libpayload.so
```

**核心条件:** 位置无关代码 (PIC/PIE) + 重定位信息 + 导出函数 = 可转 shellcode

**支持特性:** TLS (`__thread` 变量)、C++ 异常 (throw/catch)、IFUNC (memset/memcpy 等)、
DT_NEEDED 依赖库自动加载 (libz/libcrypto/libcurl 等)。

## 兼容性

Linux 3.10+ (x86_64) | Python 3.6+

| 环境 | 兼容 | 说明 |
|------|:----:|------|
| **glibc 2.17+** | ✅ | CentOS 7+ / Ubuntu / Debian / Fedora |
| **musl** | ✅ | Alpine / OpenWrt |
| **Android/Bionic** | ✅ | Android |

**支持特性:** TLS (`__thread`)、C++ 异常 (throw/catch)、IFUNC (memset/memcpy 等)、
依赖库自动加载 (libz/libcrypto/libcurl 等)。

**已验证:** C、C++、Rust (`cdylib` + `std`)

## TODO

- [ ] **i386 支持** — 32 位 syscall 封装 + bootstrap + linker.ld
- [ ] **aarch64 支持** — arm64 syscall + bootstrap
- [ ] **符号版本 (DT_VERNEED/DT_VERSYM)** — 处理 GLIBC_2.x 版本标记
- [ ] **导入混淆** — sRDI 的 Fisher-Yates 随机化 + 延迟加载
- [x] **dlopen 回退层** — 三级查找: libdl → `__libc_dlopen_mode` → linker dlopen
- [x] **双路径自解析** — link_map 快路径 (glibc/Android) + /proc/self/maps 回退 (musl)
- [x] **Bloom filter** — GNU hash 负查找 O(1) 排除
- [x] **musl 兼容** — DT_HASH 回退 + ld-musl 识别 + libc_idx=0 循环修复
- [x] **PT_GNU_RELRO** — 重定位后将 GOT 等区域 mprotect 为只读
- [x] **DT_FINI/DT_FINI_ARRAY** — 析构函数提取和存储
- [x] **C++ .eh_frame** — `__register_frame` 注册, 支持 throw/catch
- [x] **TLS (PT_TLS)** — `__thread` 变量支持, pthread + fallback 双模式

## 致谢

灵感来自 [sRDI](https://github.com/monoxgas/sRDI) (Shellcode Reflective DLL Injection)。

## 许可证

MIT
