//! This crate contains fault-injection attack prevention code for ARMv7-M processors. Includes a more
//! secure panic handler. Requires crate to be externed to use the panic handler. When a fault injection
//! attack is detected, the device will reset.

#![warn(missing_docs)]
#![no_std]

mod helper;

use core::arch::asm;
use core::hint::black_box;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

const AIRCR_ADDR: u32 = 0xE000ED0C;
const AIRCR_VECTKEY: u32 = 0x05FA << 16;
const AIRCR_SYSRESETREQ: u32 = 1 << 2;

/// A panic handler that never exits, even in cases of fault-injection attacks. Never inlined to
/// allow breakpoints to be set.
#[inline(never)]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    never_exit!()
}

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

/// State for the fault-injection attack prevention library.
pub struct FaultInjectionPrevention {
    fill_rand_slice: fn(&mut [u8]),
}

impl FaultInjectionPrevention {
    /// Initializes the state of the fault-injection attack prevention library. Takes a closure for
    /// for filling a slice with secure random bytes.
    pub fn new(fill_rand_slice: fn(&mut [u8])) -> Self {
        FaultInjectionPrevention { fill_rand_slice }
    }

    /// Ensures that if a function call is skipped, it never exits. Takes a function pointer with the
    /// AAPCS calling convention that never returns. Inlined to ensure that an attacker needs to skip
    /// more than one instruction to exit the code. For maximum security, use [`never_exit`]!() if you
    /// are defining the inner most function that never exits. Avoid relying on this function if
    /// possible.
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
    /// to exit the code.
    #[inline(always)]
    pub fn secure_reset_device() -> ! {
        helper::dsb();

        // SAFETY: AIRCR_ADDR is a valid address for the AIRCR register, and is therefore properly
        // aligned.
        unsafe {
            write_volatile(AIRCR_ADDR as *mut u32, AIRCR_VECTKEY | AIRCR_SYSRESETREQ);
        }

        helper::dsb();

        never_exit!()
    }

    /// A side-channel analysis resistant random delay function. Takes a range of possible cycles
    /// to delay for. Use [`FaultInjectionPrevention::secure_random_delay()`] instead if you don't need to specify the
    /// range. Inlined to eliminate branch to this function.
    #[inline(always)]
    pub fn secure_random_delay_cycles(&self, min_cycles: u32, max_cycles: u32) {
        todo!("Implement secure_random_delay.");
    }

    /// A side-channel analysis resistant random delay function. Delays for 10-50 cycles. Use after
    /// any externally-observable events or before operations where it is more secure to hide the
    /// timing. Inlined to eliminate branch to this function.
    #[inline(always)]
    pub fn secure_random_delay(&self) {
        self.secure_random_delay_cycles(10, 50);
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
                Self::secure_reset_device();
            }

            // SAFETY: cond is non-null and properly aligned since it comes from a Rust variable.
            unsafe {
                write_volatile(&mut cond as *mut bool, true);
            }
        }

        helper::dsb();
        self.secure_random_delay();

        if black_box(!black_box(condition())) {
            if black_box(condition()) {
                Self::secure_reset_device();
            }

            // SAFETY: cond is non-null, properly aligned, and initialized since it comes from a Rust variable.
            if unsafe { read_volatile(&cond as *const bool) } {
                Self::secure_reset_device();
            }

            // Not moving the parentheses to the outside makes smaller code.
            #[allow(clippy::unit_arg)]
            black_box(failure());
        } else {
            if black_box(!black_box(condition())) {
                Self::secure_reset_device();
            }

            // SAFETY: cond is non-null, properly aligned, and initialized since it comes from a Rust variable.
            if unsafe { !read_volatile(&cond as *const bool) } {
                Self::secure_reset_device();
            }

            // Not moving the parentheses to the outside makes smaller code.
            #[allow(clippy::unit_arg)]
            black_box(success());
        }

        helper::dsb();
    }

    pub fn critical_read<T>(&self, src: *const T) -> T
    where
        T: PartialEq + Copy + Default,
    {
        let mut data1: T = black_box(T::default());
        let mut data2: T = black_box(T::default());

        // All volatile memory reads/writes and ordering-sensitive operations
        // should use ARM dsb fence to guarantee no re-ordering in case volatile
        // is reordered due to detected no side effects
        helper::dsb();

        unsafe {
            write_volatile(black_box(&mut data1), read_volatile(black_box(src)));
        }

        unsafe {
            write_volatile(black_box(&mut data2), read_volatile(black_box(src)));
        }

        unsafe {
            write_volatile(black_box(&mut data1), read_volatile(black_box(src)));
        }

        unsafe {
            write_volatile(black_box(&mut data2), read_volatile(black_box(src)));
        }

        self.critical_if(|| data1 == data2, || (), || Self::secure_reset_device());

        unsafe {
            return read_volatile(black_box(&data1));
        }
    }

    /// The argument 'write_op' closure needs to use a volatile write function.

    /// ```
    /// let fip = FaultInjectionPrevention::new(|_| {});
    ///
    /// let mut dst: [u8; 20] = [0; 20];
    /// let src: [u8; 20] = [b'A'; 20];
    ///
    /// fip.critical_write(&mut dst as *mut [u8; 20], src, || unsafe {
    ///     core::ptr::write_volatile(&mut dst as *mut [u8; 20], src)
    /// });
    /// ```

    pub fn critical_write<T>(&self, dst: *mut T, src: T, mut write_op: impl FnMut())
    where
        T: PartialEq + Copy + Default,
    {
        // All volatile memory reads/writes and ordering-sensitive operations
        // should use ARM dsb fence to guarantee no re-ordering in case volatile
        // is reordered due to detected no side effects
        helper::dsb();

        // Sensitive memory reads should be performed multiple times, sensitive
        // writes should be verified with multiple reads, need to verify it's the
        // same each time, use volatile to ensure actual reads and writes are done

        // SAFETY:
        black_box(write_op());
        self.critical_if(
            || unsafe { read_volatile(black_box(dst)) == read_volatile(black_box(&src)) },
            || (),
            || Self::secure_reset_device(),
        );

        black_box(write_op());
        self.critical_if(
            || unsafe { read_volatile(black_box(dst)) == read_volatile(black_box(&src)) },
            || (),
            || Self::secure_reset_device(),
        );

        black_box(write_op());
        self.critical_if(
            || unsafe { read_volatile(black_box(dst)) == read_volatile(black_box(&src)) },
            || (),
            || Self::secure_reset_device(),
        );
    }
}
