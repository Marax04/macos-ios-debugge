// Exercises: struct field recovery, loop-flag conditions, slice indexing.
// #[no_mangle] + extern "C" keep symbol names and the SysV/Win64 ABI clean so
// the decompiled output is comparable to the C/C++ samples.

#[repr(C)]
pub struct Point {
    pub x: i64,
    pub y: i64,
    pub sum: i64,
}

#[no_mangle]
pub extern "C" fn accumulate(pts: *mut Point, n: i32) -> i64 {
    let mut total: i64 = 0;
    let mut i = 0i32;
    while i < n {
        unsafe {
            let p = &mut *pts.offset(i as isize);
            p.sum = p.x + p.y;
            total += p.sum;
        }
        i += 1;
    }
    total
}

#[no_mangle]
pub extern "C" fn find_max(arr: *const i64, len: usize) -> i64 {
    unsafe {
        let mut best = *arr;
        let mut i = 1usize;
        while i < len {
            let v = *arr.add(i);
            if v > best {
                best = v;
            }
            i += 1;
        }
        best
    }
}

fn main() {
    let mut pts = [
        Point { x: 1, y: 2, sum: 0 },
        Point { x: 3, y: 4, sum: 0 },
        Point { x: 5, y: 6, sum: 0 },
    ];
    let t = accumulate(pts.as_mut_ptr(), 3);
    let arr = [10i64, 40, 20, 30];
    let m = find_max(arr.as_ptr(), 4);
    std::process::exit((t + m) as i32);
}
