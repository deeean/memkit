use std::io::{self, BufRead, Write};

#[repr(C)]
struct TestData {
    u8_val: u8,
    i8_val: i8,
    u16_val: u16,
    i16_val: i16,
    u32_val: u32,
    i32_val: i32,
    u64_val: u64,
    i64_val: i64,
    f32_val: f32,
    f64_val: f64,
    string_val: [u8; 32],
    // pattern: a known byte sequence for pattern scanning
    pattern: [u8; 8],
}

fn main() {
    let mut string_buf = [0u8; 32];
    let msg = b"Hello memkit!";
    string_buf[..msg.len()].copy_from_slice(msg);

    let data = TestData {
        u8_val: 0xAB,
        i8_val: -42,
        u16_val: 0xBEEF,
        i16_val: -1234,
        u32_val: 0xDEADBEEF,
        i32_val: -123456,
        u64_val: 0xCAFEBABE_DEADBEEF,
        i64_val: -9876543210,
        f32_val: 3.14,
        f64_val: 2.718281828,
        string_val: string_buf,
        pattern: [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
    };

    let addr = &data as *const TestData as usize;

    // Print PID and address so the test can find us
    println!("PID:{}", std::process::id());
    println!("ADDR:0x{:X}", addr);
    let _ = io::stdout().flush();

    // Wait for stdin to close (test process will kill us)
    let stdin = io::stdin();
    let _ = stdin.lock().lines().next();
}
