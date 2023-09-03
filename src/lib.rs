//! This crate contains fault-injection attack prevention code for ARM processors.

#![warn(missing_docs)]
#![no_std]

use core::arch::asm;
use core::hint::black_box;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};

/// State for the fault-injection attack prevention library.
pub struct FaultInjectionPrevention<D, F>
where
    D: FnMut(u32),
    F: FnMut(&mut [u8]),
{
    delay_ms: D,
    fill_rand_slice: F,
}

impl<D, F> FaultInjectionPrevention<D, F>
where
    D: FnMut(u32),
    F: FnMut(&mut [u8]),
{
    /// Initializes the state of the fault-injection attack prevention library. Takes two closures,
    /// one for delaying for a given number of milliseconds, and one for filling a slice with random
    /// bytes. The fill_rand_slice closure should come from a fairly secure source.
    pub fn new(mut delay_ms: impl FnMut(u32), mut fill_rand_slice: impl FnMut(&mut [u8])) {
        //
    }

    /// To be used for a critical if statement that should be resistant to fault-injection attacks.
    /// Takes a condition closure, a success closure, and a failure closure. The success and failure
    /// closures should match the success and failure cases of the code that is being run to ensure
    /// maximum protection.
    #[inline(never)]
    fn critical_if(
        &self,
        mut condition: impl FnMut() -> bool,
        success: impl FnOnce(),
        failure: impl FnOnce(),
    ) {
        let mut cond = false;

        // Default to false, use volatile to ensure the write actually occurs.
        // SAFETY: cond is non-null and properly aligned since it comes from a Rust variable.
        unsafe {
            write_volatile(&mut cond as *mut bool, false);
        }

        if black_box(!black_box(condition())) {
            // SAFETY: cond is non-null and properly aligned since it comes from a Rust variable.
            unsafe {
                write_volatile(&mut cond as *mut bool, false);
            }
        } else {
            if black_box(!black_box(condition())) {
                panic!("Fault injection detected!");
            }

            // SAFETY: cond is non-null and properly aligned since it comes from a Rust variable.
            unsafe {
                write_volatile(&mut cond as *mut bool, true);
            }
        }

        compiler_fence(Ordering::SeqCst);

        unsafe { asm!("dsb") }

        compiler_fence(Ordering::SeqCst);

        if black_box(!black_box(condition())) {
            if black_box(condition()) {
                panic!("Fault injection detected!");
            }

            // SAFETY: cond is non-null, properly aligned, and initialized since it comes from a Rust variable.
            if unsafe { read_volatile(&cond as *const bool) } {
                panic!("Fault injection detected!");
            }

            // Not moving the parentheses to the outside makes smaller code.
            #[allow(clippy::unit_arg)]
            black_box(failure());
        } else {
            if black_box(!black_box(condition())) {
                panic!("Fault injection detected!");
            }

            // SAFETY: cond is non-null, properly aligned, and initialized since it comes from a Rust variable.
            if unsafe { !read_volatile(&cond as *const bool) } {
                panic!("Fault injection detected!");
            }

            // Not moving the parentheses to the outside makes smaller code.
            #[allow(clippy::unit_arg)]
            black_box(success());
        }

        compiler_fence(Ordering::SeqCst);

        unsafe { asm!("dsb") }

        compiler_fence(Ordering::SeqCst);
    }
}
