use std::os::raw::c_int;

static mut G_COUNTER: c_int = 0;

#[no_mangle]
pub unsafe extern "C" fn rust_std_run(user_data: *const u8, user_data_len: u32) -> c_int {
    G_COUNTER += 1;

    eprintln!("[rust_std] hello from std shellcode!");
    eprintln!("[rust_std] counter = {}", G_COUNTER);

    if !user_data.is_null() && user_data_len > 0 {
        let s = std::str::from_utf8_unchecked(std::slice::from_raw_parts(user_data, user_data_len as usize));
        eprintln!("[rust_std] user_data: {}", s);
    }

    let v: Vec<i32> = (1..=10).collect();
    let sum: i32 = v.iter().sum();
    eprintln!("[rust_std] 1+2+...+10 = {}", sum);

    let s = format!("formatted string: {} * {} = {}", 6, 7, 6 * 7);
    eprintln!("[rust_std] {}", s);

    test_panic_catch();
    test_thread_local();
    test_closure();

    eprintln!("[rust_std] all good!");
    G_COUNTER
}

fn test_panic_catch() {
    let result = std::panic::catch_unwind(|| {
        eprintln!("[rust_std] inside catch_unwind");
    });
    match result {
        Ok(()) => eprintln!("[rust_std] catch_unwind ok"),
        Err(_) => eprintln!("[rust_std] catch_unwind FAILED"),
    }
}

use std::cell::Cell;

thread_local! {
    static TLS_COUNTER: Cell<u32> = Cell::new(0);
}

fn test_thread_local() {
    TLS_COUNTER.with(|c| {
        c.set(c.get() + 1);
        eprintln!("[rust_std] TLS counter = {}", c.get());
    });
    TLS_COUNTER.with(|c| {
        c.set(c.get() + 1);
        eprintln!("[rust_std] TLS counter = {}", c.get());
    });
}

fn test_closure() {
    let x = 42;
    let add = |y: i32| x + y;
    eprintln!("[rust_std] closure: 42 + 8 = {}", add(8));
}

#[no_mangle]
pub unsafe extern "C" fn rust_std_add(a: c_int, b: c_int) -> c_int {
    a + b
}
