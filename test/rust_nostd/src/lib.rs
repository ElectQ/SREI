#![no_std]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

static mut G_COUNTER: u32 = 0;

unsafe fn sys_write(fd: i32, buf: *const u8, len: usize) {
    let mut written = 0usize;
    while written < len {
        let n: usize;
        core::arch::asm!(
            "syscall",
            inlateout("rax") 1u64 => n,
            in("rdi") fd as u64,
            in("rsi") buf.add(written) as u64,
            in("rdx") (len - written) as u64,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
        if n <= 0 {
            break;
        }
        written += n as usize;
    }
}

unsafe fn sys_exit(code: i32) -> ! {
    core::arch::asm!(
        "syscall",
        in("rax") 60u64,
        in("rdi") code as u64,
        options(noreturn),
    );
}

unsafe fn print_str(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

unsafe fn uint_to_str(mut n: u32, buf: &mut [u8; 12]) -> &str {
    if n == 0 {
        buf[0] = b'0';
        return core::str::from_utf8_unchecked(&buf[..1]);
    }
    let mut pos = 12;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    core::str::from_utf8_unchecked(&buf[pos..])
}

#[no_mangle]
pub unsafe extern "C" fn rust_nostd_run(user_data: *const u8, user_data_len: u32) -> i32 {
    G_COUNTER += 1;

    print_str("[rust_nostd] hello from no_std shellcode!\n");
    print_str("[rust_nostd] counter = ");
    let mut buf = [0u8; 12];
    print_str(uint_to_str(G_COUNTER, &mut buf));
    print_str("\n");

    if !user_data.is_null() && user_data_len > 0 {
        print_str("[rust_nostd] user_data: ");
        sys_write(1, user_data, user_data_len as usize);
        print_str("\n");
    }

    let sum = (1..=10u32).fold(0u32, |a, b| a + b);
    print_str("[rust_nostd] 1+2+...+10 = ");
    print_str(uint_to_str(sum, &mut buf));
    print_str("\n");

    print_str("[rust_nostd] all good!\n");
    G_COUNTER as i32
}

#[no_mangle]
pub unsafe extern "C" fn rust_nostd_add(a: i32, b: i32) -> i32 {
    a + b
}
