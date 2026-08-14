// Broad Rust feature coverage for decompiler RE testing:
//  - enums + exhaustive match (tagged unions)
//  - traits + dynamic dispatch (Box<dyn Trait> vtables) + generics (monomorphized)
//  - Option / Result / `?` error propagation
//  - iterators / closures / fold / map / filter
//  - Vec, String, slices, Box heap allocation
//  - pattern matching, overflow-checked arithmetic

#[derive(Clone, Copy)]
enum Op {
    Add(i64, i64),
    Sub(i64, i64),
    Mul(i64, i64),
    Neg(i64),
}

fn eval(op: Op) -> i64 {
    match op {
        Op::Add(a, b) => a.wrapping_add(b),
        Op::Sub(a, b) => a.wrapping_sub(b),
        Op::Mul(a, b) => a.wrapping_mul(b),
        Op::Neg(a) => a.wrapping_neg(),
    }
}

trait Area {
    fn area(&self) -> f64;
}
struct Circle {
    r: f64,
}
struct Rect {
    w: f64,
    h: f64,
}
impl Area for Circle {
    fn area(&self) -> f64 {
        std::f64::consts::PI * self.r * self.r
    }
}
impl Area for Rect {
    fn area(&self) -> f64 {
        self.w * self.h
    }
}

// Generic (monomorphized) function.
fn sum_of<T: Copy + Into<i64>>(xs: &[T]) -> i64 {
    let mut acc = 0i64;
    for &x in xs {
        acc = acc.wrapping_add(x.into());
    }
    acc
}

// Result + `?`.
fn parse_and_div(a: &str, b: &str) -> Result<i64, std::num::ParseIntError> {
    let x: i64 = a.parse()?;
    let y: i64 = b.parse()?;
    Ok(if y == 0 { 0 } else { x / y })
}

#[no_mangle]
pub extern "C" fn compute(n: i32) -> i64 {
    // Dynamic dispatch through trait objects (vtables).
    let shapes: Vec<Box<dyn Area>> = vec![
        Box::new(Circle { r: 2.0 }),
        Box::new(Rect { w: 3.0, h: 4.0 }),
    ];
    let area_sum: f64 = shapes.iter().map(|s| s.area()).sum();

    // Iterator chain: map + filter + fold.
    let iter_sum: i64 = (1..=n as i64)
        .map(|x| x * x)
        .filter(|x| x % 2 == 0)
        .fold(0i64, |a, x| a.wrapping_add(x));

    // Enum eval + slice generic.
    let ops = [Op::Add(3, 4), Op::Mul(5, 6), Op::Neg(7), Op::Sub(10, 2)];
    let op_sum: i64 = ops.iter().map(|&o| eval(o)).sum();
    let nums: [i32; 4] = [10, 20, 30, 40];
    let gsum = sum_of(&nums);

    // Option + Result.
    let opt = Some(area_sum as i64).filter(|&v| v > 0).unwrap_or(-1);
    let divr = parse_and_div("100", "5").unwrap_or(0);

    iter_sum
        .wrapping_add(op_sum)
        .wrapping_add(gsum)
        .wrapping_add(opt)
        .wrapping_add(divr)
}

fn main() {
    std::process::exit(compute(8) as i32);
}
