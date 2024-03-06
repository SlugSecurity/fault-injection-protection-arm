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
use core::result::Result;
use cortex_m::delay::Delay;
use rand_core::CryptoRngCore;
extern crate const_random;

// Application Interrupt and Reset Control Register
const AIRCR_ADDR: u32 = 0xE000ED0C;
const AIRCR_VECTKEY: u32 = 0x05FA << 16;
const AIRCR_SYSRESETREQ: u32 = 1 << 2;

const CRITICAL_BOOL: usize = const_random::const_random!(usize);
const CRITICAL_ERROR: usize = const_random::const_random!(usize);

#[allow(missing_docs)]
#[derive(PartialEq, Eq, Clone, Copy)]
#[repr(usize)]
/// Large constants values for true and false. This makes it so attackers need
/// to do more than flip a signle bit for a true/false flip.
pub enum SecureBool {
    True = CRITICAL_BOOL,
    False = !CRITICAL_BOOL,
    Error = CRITICAL_ERROR,
}

impl From<bool> for SecureBool {
    fn from(cond: bool) -> SecureBool {
        match cond {
            true => SecureBool::True,
            false => SecureBool::False,
        }
    }
}

/// Secure random delay errors
///
/// # Errors
/// * `InvalidRange` - The provided values are out of an expected range.
#[derive(Debug)]
pub enum RandomError {
    /// The provided range is invalid. This can occur if the minimum value is greater than the maximum value.
    InvalidRange,
}

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
pub struct FaultInjectionPrevention {}

impl FaultInjectionPrevention {
    /// Initializes the state of the fault-injection attack prevention library.
    pub fn new() -> Self {
        FaultInjectionPrevention {}
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

    /// Generates a secure random number within the specified range.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure rng
    /// * `min` - The minimum value of the range.
    /// * `max` - The maximum value of the range.
    ///
    /// # Returns
    /// A `Result` containing the random number or an error message.
    fn generate_secure_random(
        rng: &mut impl CryptoRngCore,
        min: u32,
        max: u32,
    ) -> Result<u32, RandomError> {
        if min > max {
            return Err(RandomError::InvalidRange);
        }
        let range = max - min + 1;
        let random_value = rng.next_u32() % range + min;
        Ok(random_value)
    }

    /// A side-channel analysis resistant random delay function. Takes a range of possible ms
    /// to delay for. Use [`FaultInjectionPrevention::secure_random_delay()`] instead if you don't need to specify the
    /// range. Inlined to eliminate branch to this function.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure rng
    /// * `min_ms` - The minimum number of ms to delay.
    /// * `max_ms` - The maximum number of ms to delay.
    /// * `delay` - Delay instance
    ///
    /// # Safety
    /// This function assumes that `cortex-m::delay::Delay` is safe.
    #[inline(always)]
    pub fn secure_random_delay_ms(
        &self,
        rng: &mut impl CryptoRngCore,
        min_ms: u32,
        max_ms: u32,
        delay: &mut Delay,
    ) -> Result<(), RandomError> {
        match Self::generate_secure_random(rng, min_ms, max_ms) {
            Ok(random_ms) => {
                delay.delay_ms(random_ms);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// A side-channel analysis resistant random delay function. Delays for 10-50 ms. Use after
    /// any externally-observable events or before operations where it is more secure to hide the
    /// timing. Inlined to eliminate branch to this function.
    ///
    /// # Safety
    /// This function assumes that `cortex-m::delay::Delay` is safe.
    #[inline(always)]
    pub fn secure_random_delay(
        &self,
        rng: &mut impl CryptoRngCore,
        delay: &mut Delay,
    ) -> Result<(), RandomError> {
        self.secure_random_delay_ms(rng, 10, 50, delay)
    }

    /// To be used for a critical if statement that should be resistant to fault-injection attacks.
    /// Takes a condition closure, a success closure, and a failure closure. The success and failure
    /// closures should match the success and failure cases of the code that is being run to ensure
    /// maximum protection.
    pub fn critical_if(
        &self,
        mut condition: impl FnMut() -> SecureBool,
        success: impl FnOnce(),
        failure: impl FnOnce(),
    ) {
        let mut cond = SecureBool::Error;

        // Default to error, use volatile to ensure the write actually occurs.
        // SAFETY: cond is non-null and properly aligned since it comes from a
        // Rust variable. In addition SecureBool derives the Copy trait, so a
        // bit-wise copy is performed
        unsafe {
            write_volatile(&mut cond, SecureBool::Error);
        }

        if black_box(black_box(condition()) == SecureBool::False) {
            // SAFETY: cond is non-null and properly aligned since it comes from a
            // Rust variable. In addition SecureBool derives the Copy trait, so a
            // bit-wise copy is performed
            unsafe {
                write_volatile(&mut cond, SecureBool::False);
            }
        } else {
            if black_box(black_box(condition()) == SecureBool::False) {
                Self::secure_reset_device();
            }

            // SAFETY: cond is non-null and properly aligned since it comes from a
            // Rust variable. In addition SecureBool derives the Copy trait, so a
            // bit-wise copy is performed
            unsafe {
                write_volatile(&mut cond, SecureBool::True);
            }
        }

        helper::dsb();
        // PLS FIX
        //self.secure_random_delay();

        if black_box(black_box(condition()) == SecureBool::False) {
            if black_box(black_box(condition()) == SecureBool::True) {
                Self::secure_reset_device();
            }

            // SAFETY: cond is non-null, properly aligned, and initialized since it comes from a Rust variable.
            if unsafe { read_volatile(&cond) != SecureBool::False } {
                Self::secure_reset_device();
            }

            // Not moving the parentheses to the outside makes smaller code.
            #[allow(clippy::unit_arg)]
            black_box(failure());
        } else {
            if black_box(black_box(condition()) == SecureBool::False) {
                Self::secure_reset_device();
            }

            // SAFETY: cond is non-null, properly aligned, and initialized since it comes from a Rust variable.
            if unsafe { read_volatile(&cond) != SecureBool::True } {
                Self::secure_reset_device();
            }

            // Not moving the parentheses to the outside makes smaller code.
            #[allow(clippy::unit_arg)]
            black_box(success());
        }

        helper::dsb();
    }

    /// To be used for a critical memory reads that should be resistant to
    /// fault-injection attacks. If a fault injection is detected, the board
    /// securely resets itself.

    #[inline(always)]
    pub fn critical_read<T>(&self, src: &T) -> T
    where
        T: Eq + Copy + Default,
    {
        let mut data1: T = black_box(T::default());
        let mut data2: T = black_box(T::default());

        // All volatile memory reads/writes and ordering-sensitive operations
        // should use ARM dsb fence to guarantee no re-ordering in case volatile
        // is reordered due to detected no side effects
        helper::dsb();

        // SAFETY:
        // * src is valid for reads because it is a rust reference
        //
        // * src is properly initialized
        //
        // * src is pointing to a properly aligned value of type T because it is
        // a rust refernce
        //
        // * dst is be valid for writes because type T must implement the
        // default trait.
        //
        // * dst is properly aligned

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

        self.critical_if(
            || (data1 == data2).into(),
            || (),
            || Self::secure_reset_device(),
        );

        black_box(data1)
    }

    /// To be used for a critical memory write that should be resistant to
    /// fault-injection attacks. The write operation closure argument should be
    /// a call to the write operation that needs to be redundent.
    ///
    /// If a fault injection is detected, the board securely resets itself.

    ///
    /// # Safety
    ///
    /// Callers must ensure that the following condition is met:
    /// * The 'write_op' clousure must use a volatile write function.
    /// * src is valid for reads
    /// * src is properly initialized
    /// * src is pointing to a properly aligned value of type T
    /// * dst must be valid for writes
    /// * dst must be properly aligned

    /// ```
    /// let fip = FaultInjectionPrevention::new(|_| {});
    ///
    /// let mut buffer: [u8; 20] = [0; 20];
    /// let data: [u8; 20] = [b'A'; 20];
    ///
    /// unsafe {
    ///    fip.critical_write(&mut buffer, data, |dst, src| write_volatile(dst, src));
    /// }
    ///
    /// // 'from_ref' is available in rust version 1.76.0
    /// unsafe {
    ///    fip.critical_write(&mut buffer, data, |dst, src| {
    ///         flash_controller.write(from_ref(dst) as u32, &src, &SystemClock)
    ///    });
    /// }
    /// ```

    #[inline(always)]
    pub unsafe fn critical_write<T>(&self, dst: &mut T, src: T, mut write_op: impl FnMut(&mut T, T))
    where
        T: Eq + Copy + Default,
    {
        // All volatile memory reads/writes and ordering-sensitive operations
        // should use ARM dsb fence to guarantee no re-ordering in case volatile
        // is reordered due to detected no side effects
        helper::dsb();

        write_op(black_box(dst), black_box(src));
        self.critical_if(
            || unsafe { (read_volatile(black_box(dst)) == read_volatile(black_box(&src))).into() },
            || (),
            || Self::secure_reset_device(),
        );

        write_op(black_box(dst), black_box(src));
        self.critical_if(
            || unsafe { (read_volatile(black_box(dst)) == read_volatile(black_box(&src))).into() },
            || (),
            || Self::secure_reset_device(),
        );

        write_op(black_box(dst), black_box(src));
        self.critical_if(
            || unsafe { (read_volatile(black_box(dst)) == read_volatile(black_box(&src))).into() },
            || (),
            || Self::secure_reset_device(),
        );
    }
}

impl Default for FaultInjectionPrevention {
    fn default() -> Self {
        Self::new()
    }
}
