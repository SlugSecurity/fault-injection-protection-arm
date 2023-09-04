//! This crate contains fault-injection attack prevention code for ARM processors. Includes a more
//! secure panic handler. Requires crate to be externed to use the panic handler.

#![warn(missing_docs)]
#![no_std]

use core::arch::asm;
use core::hint::black_box;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};

/// A macro for ensuring that code never exits, even in cases of fault-injection attacks.
#[macro_export]
macro_rules! never_exit {
    () => {
        // SAFETY: All branches are to a local label.
        unsafe {
            // 2b or 2b, that is the question.
            asm!(
                "2:",
                "b 2b",
                "b 2b",
                "b 2b",
                "b 2b",
                "b 2b",
                "b 2b",
                "b 2b",
                "b 2b",
                "b 2b",
                "b 2b",
                "b 2b",
                options(noreturn),
            )
        }
    };
}

/// A panic handler that never exits, even in cases of fault-injection attacks. Never inlined to
/// allow breakpoints to be set.
#[inline(never)]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    never_exit!()
}

/// State for the fault-injection attack prevention library.
pub struct FaultInjectionPrevention {
    fill_rand_slice: fn(&mut [u8]),
    reset_device: extern "aapcs" fn() -> !,
}

impl FaultInjectionPrevention {
    /// Initializes the state of the fault-injection attack prevention library. Takes a closure for
    /// for filling a slice with secure random bytes. Takes a closure for resetting the device, which
    /// is used when a fault-injection attack is detected.
    pub fn new(fill_rand_slice: fn(&mut [u8]), reset_device: extern "aapcs" fn() -> !) -> Self {
        FaultInjectionPrevention {
            fill_rand_slice,
            reset_device,
        }
    }

    /// Ensures that if a function call is skipped, it never exits. Takes a function pointer with the
    /// AAPCS calling convention that never returns. Inlined to ensure that an attacker needs to skip
    /// more than one instruction to skip the loop. Use [`never_exit`]!() if you are defining the inner
    /// most function that never exits for maximum security.
    #[inline(always)]
    pub fn secure_never_exit_func(func: extern "aapcs" fn() -> !) -> ! {
        // SAFETY: func is a valid function pointer with the AAPCS calling convention.
        unsafe {
            // Use asm to eliminate dead code optimization from optimizing out never_exit!().
            asm!(
                "b {}",
                in(reg) func,
                clobber_abi("aapcs"),
            )
        }

        never_exit!()
    }

    /// Securely resets the device, ensuring that if an attacker skips the reset, they do not break
    /// into other code. Inlined to ensure that the attacker needs to skip more than one instruction
    /// to skip the loop.
    #[inline(always)]
    pub fn secure_reset_device(&self) -> ! {
        // TODO: See if we can reset the device without having the user pass in a function pointer.
        // Instead, do it on our own and use never_exit!().
        Self::secure_never_exit_func(self.reset_device)
    }

    /// A side-channel analysis resistant random delay function. Takes a range of possible cycles
    /// to delay for. Use [`self::secure_random_delay()`] instead if you don't need to specify the
    /// range. Inlined to eliminate branch to this function.
    #[inline(always)]
    pub fn secure_random_delay_cycles(min_cycles: u32, max_cycles: u32) {
        todo!("Implement secure_random_delay.");
    }

    /// A side-channel analysis resistant random delay function. Delays for 10-50 cycles. Use after
    /// any externally-observable events or before operations where it is more secure to hide the
    /// timing. Inlined to eliminate branch to this function.
    #[inline(always)]
    pub fn secure_random_delay() {
        Self::secure_random_delay_cycles(10, 50);
    }

    /// To be used for a critical if statement that should be resistant to fault-injection attacks.
    /// Takes a condition closure, a success closure, and a failure closure. The success and failure
    /// closures should match the success and failure cases of the code that is being run to ensure
    /// maximum protection.
    pub fn critical_if(
        &self,
        mut condition: impl FnMut() -> bool,
        success: impl FnOnce(),
        failure: impl FnOnce(),
    ) {
        // TODO: Use enum with constant large values for true, false, and error. Default to error.
        // When checking for error case, check for not true and not false in case initializing with
        // error value was skipped. Warning below is for tracking this TODO.
        let x = 5;
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
                self.secure_reset_device();
            }

            // SAFETY: cond is non-null and properly aligned since it comes from a Rust variable.
            unsafe {
                write_volatile(&mut cond as *mut bool, true);
            }
        }

        compiler_fence(Ordering::SeqCst);

        // SAFETY: "dsb" is always safe.
        unsafe { asm!("dsb") }

        compiler_fence(Ordering::SeqCst);
        Self::secure_random_delay();

        if black_box(!black_box(condition())) {
            if black_box(condition()) {
                self.secure_reset_device();
            }

            // SAFETY: cond is non-null, properly aligned, and initialized since it comes from a Rust variable.
            if unsafe { read_volatile(&cond as *const bool) } {
                self.secure_reset_device();
            }

            // Not moving the parentheses to the outside makes smaller code.
            #[allow(clippy::unit_arg)]
            black_box(failure());
        } else {
            if black_box(!black_box(condition())) {
                self.secure_reset_device();
            }

            // SAFETY: cond is non-null, properly aligned, and initialized since it comes from a Rust variable.
            if unsafe { !read_volatile(&cond as *const bool) } {
                self.secure_reset_device();
            }

            // Not moving the parentheses to the outside makes smaller code.
            #[allow(clippy::unit_arg)]
            black_box(success());
        }

        compiler_fence(Ordering::SeqCst);

        // SAFETY: "dsb" is always safe.
        unsafe { asm!("dsb") }

        compiler_fence(Ordering::SeqCst);
    }
}
