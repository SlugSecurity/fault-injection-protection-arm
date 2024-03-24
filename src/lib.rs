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
use cortex_m::asm::delay;
use rand_core::CryptoRngCore;
extern crate const_random;

/// Global stack that pushes new stack canaries onto non-stack memory
struct RefCanaryStack {
    reference_canary_vec: [u64; 50],
    counter: usize,
}

impl RefCanaryStack {
    /// Creates a new canary stack.
    /// # Safety: Must allocate in non-stack memory
    const fn new() -> Self {
        RefCanaryStack {
            reference_canary_vec: [0u64; 50],
            counter: 0,
        }
    }

    /// Pushes a new stack canary reference on the stack.
    #[inline(always)]
    fn push(
        &mut self,
        new_canary: u64,
        fip: &FaultInjectionPrevention,
        rng: &mut impl CryptoRngCore,
    ) {
        if self.counter >= self.reference_canary_vec.len() - 1 {
            panic!()
        }

        // need extra variable to because `self.counter` is mutably borrowed
        let current_counter = self.counter;

        // increase stack canary stack count
        fip.critical_write(
            &mut self.counter,
            black_box(current_counter + 1),
            unsafe { |dst, src| write_volatile(dst, src) },
            rng,
        );

        // push new stack canary onto the stack
        fip.critical_write(
            &mut self.reference_canary_vec[self.counter],
            new_canary,
            unsafe { |dst, src| write_volatile(dst, src) },
            rng,
        );
    }

    /// Removes the newest stack canary reference off of the stack.
    /// # Safety: Must be called at the end of a critical function to compare
    /// the actaul stack canary value with the reference canary value
    #[inline(always)]
    fn pop(&mut self, fip: &FaultInjectionPrevention, rng: &mut impl CryptoRngCore) -> u64 {
        let popped_value = self.reference_canary_vec[self.counter];

        // need extra variable to because `self.counter` is mutably borrowed
        let current_counter = self.counter;

        // decrease stack canary stack counter
        fip.critical_write(
            &mut self.counter,
            black_box(current_counter - 1),
            unsafe { |dst, src| write_volatile(dst, src) },
            rng,
        );

        popped_value
    }

    /// Returns the newest stack canary reference on the stack
    #[inline(always)]
    fn peek(&self) -> u64 {
        self.reference_canary_vec[self.counter]
    }
}

static mut REF_CANARY: RefCanaryStack = RefCanaryStack::new();

// Application Interrupt and Reset Control Register
const AIRCR_ADDR: u32 = 0xE000ED0C;
const AIRCR_VECTKEY: u32 = 0x05FA << 16;
const AIRCR_SYSRESETREQ: u32 = 1 << 2;

const CRITICAL_BOOL: usize = const_random::const_random!(usize);
const CRITICAL_ERROR: usize = const_random::const_random!(usize);

#[allow(missing_docs)]
#[derive(PartialEq, Eq, Clone, Copy, Default)]
#[repr(usize)]
/// Large constants values for true and false. This makes it so attackers need
/// to do more than flip a signle bit for a true/false flip.
pub enum SecureBool {
    True = CRITICAL_BOOL,
    False = !CRITICAL_BOOL,
    #[default]
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
    pub fn generate_secure_random(
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

    /// A side-channel analysis resistant random delay function. Takes a range of possible cycles
    /// to delay for. Use [`FaultInjectionPrevention::secure_random_delay()`] instead if you don't need to specify the
    /// range. Inlined to eliminate branch to this function.
    ///
    /// Returns an error if invalid range, i.e. `min_ms` is greater than `max_ms`.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure rng
    /// * `min_cycles` - The minimum number of cycles to delay.
    /// * `max_cycles` - The maximum number of cycles to delay.
    /// * `delay` - Delay instance
    #[inline(always)]
    pub fn secure_random_delay_cycles(
        &self,
        rng: &mut impl CryptoRngCore,
        min_cycles: u32,
        max_cycles: u32,
    ) -> Result<(), RandomError> {
        let random_cycles = Self::generate_secure_random(rng, min_cycles, max_cycles)?;
        delay(random_cycles);
        Ok(())
    }

    /// A side-channel analysis resistant random delay function. Delays for 10-50 cycles. Use after
    /// any externally-observable events or before operations where it is more secure to hide the
    /// timing. Inlined to eliminate branch to this function.
    #[inline(always)]
    pub fn secure_random_delay(&self, rng: &mut impl CryptoRngCore) {
        self.secure_random_delay_cycles(rng, 10, 50).unwrap();
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
        rng: &mut impl CryptoRngCore,
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

        self.secure_random_delay(rng);

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

    /// Stack canaries should be used anywhere where there is user input or
    /// potential for user input, so overflow via glitching is difficult at
    /// these points
    /// ```
    /// let mut user_input = [b'A'; 100];
    /// let mut buffer: [u8; 16] = [0; 16];
    /// fip.stack_canary(|| unsafe {
    ///     copy(user_input.as_ptr(), buffer.as_mut_ptr(), user_input.len())
    /// });
    /// ```

    #[inline(never)]
    pub fn stack_canary(&self, run: impl FnOnce(), rng: &mut impl CryptoRngCore) {
        // force canary to be allocated to stack instead of register
        let mut canary: u64 = black_box(0);

        // SAFETY: No race conditions because this library only supports single
        // threaded programs
        unsafe {
            // generate a new global canary at runtime using CryptoRngCore
            // reference stored in fip struct
            REF_CANARY.push(rng.next_u64(), self, rng);

            self.critical_write(
                &mut canary,
                REF_CANARY.peek(),
                |dst, src| write_volatile(dst, src),
                rng,
            );
        }

        helper::dsb();
        run();

        let reference_canary = unsafe { REF_CANARY.pop(self, rng) };
        self.critical_if(
            || (canary == reference_canary).into(),
            || (),
            || Self::secure_reset_device(),
            rng,
        );
    }

    /// To be used for a critical memory reads that should be resistant to
    /// fault-injection attacks. If a fault injection is detected, the board
    /// securely resets itself.

    #[inline(always)]
    pub fn critical_read<T>(&self, src: &T, rng: &mut impl CryptoRngCore) -> T
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
            rng,
        );

        black_box(data1)
    }

    /// To be used for critical memory writes that need to be resilient to
    /// fault-injection attacks. The `write_op` closure must use a volatile
    /// write function.
    ///
    /// If a fault injection is detected, the board securely resets itself.
    ///
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
    pub fn critical_write<T>(
        &self,
        dst: &mut T,
        src: T,
        mut write_op: impl FnMut(&mut T, T),
        rng: &mut impl CryptoRngCore,
    ) where
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
            rng,
        );

        write_op(black_box(dst), black_box(src));
        self.critical_if(
            || unsafe { (read_volatile(black_box(dst)) == read_volatile(black_box(&src))).into() },
            || (),
            || Self::secure_reset_device(),
            rng,
        );

        write_op(black_box(dst), black_box(src));
        self.critical_if(
            || unsafe { (read_volatile(black_box(dst)) == read_volatile(black_box(&src))).into() },
            || (),
            || Self::secure_reset_device(),
            rng,
        );
    }
}

impl Default for FaultInjectionPrevention {
    fn default() -> Self {
        Self::new()
    }
}
