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
use rand_core::CryptoRngCore;

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
    fn push(&mut self, new_canary: u64) {
        if self.counter >= self.reference_canary_vec.len() - 1 {
            panic!()
        }

        self.counter += 1;
        self.reference_canary_vec[self.counter] = new_canary;
    }

    /// Removes the newest stack canary reference off of the stack.
    /// # Safety: Must be called at the end of a critical function to compare
    /// the actaul stack canary value with the reference canary value
    #[inline(always)]
    fn pop(&mut self) -> u64 {
        let popped_value = self.reference_canary_vec[self.counter];
        self.reference_canary_vec[self.counter] = 0u64;
        self.counter -= 1;
        popped_value
    }

    /// Returns the newest stack canary reference on the stack
    #[inline(always)]
    fn peek(&self) -> u64 {
        self.reference_canary_vec[self.counter]
    }
}

static mut REF_CANARY: RefCanaryStack = RefCanaryStack::new();

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
pub fn secure_random_delay_cycles(min_cycles: u32, max_cycles: u32) {
    todo!("Implement secure_random_delay.");
}

/// A side-channel analysis resistant random delay function. Delays for 10-50 cycles. Use after
/// any externally-observable events or before operations where it is more secure to hide the
/// timing. Inlined to eliminate branch to this function.
#[inline(always)]
pub fn secure_random_delay() {
    secure_random_delay_cycles(10, 50);
}

/// To be used for a critical if statement that should be resistant to fault-injection attacks.
/// Takes a condition closure, a success closure, and a failure closure. The success and failure
/// closures should match the success and failure cases of the code that is being run to ensure
/// maximum protection.
pub fn critical_if(
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
            secure_reset_device();
        }

        // SAFETY: cond is non-null and properly aligned since it comes from a Rust variable.
        unsafe {
            write_volatile(&mut cond as *mut bool, true);
        }
    }

    helper::dsb();
    secure_random_delay();

    if black_box(!black_box(condition())) {
        if black_box(condition()) {
            secure_reset_device();
        }

        // SAFETY: cond is non-null, properly aligned, and initialized since it comes from a Rust variable.
        if unsafe { read_volatile(&cond as *const bool) } {
            secure_reset_device();
        }

        // Not moving the parentheses to the outside makes smaller code.
        #[allow(clippy::unit_arg)]
        black_box(failure());
    } else {
        if black_box(!black_box(condition())) {
            secure_reset_device();
        }

        // SAFETY: cond is non-null, properly aligned, and initialized since it comes from a Rust variable.
        if unsafe { !read_volatile(&cond as *const bool) } {
            secure_reset_device();
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
pub fn stack_canary(run: impl FnOnce(), rng: &mut impl CryptoRngCore) {
    // force canary to be allocated to stack instead of register
    let mut canary: u64 = black_box(0);

    // SAFETY: Mutating a global variable is safe because we do not have race-conditions
    unsafe {
        // generate a new global canary at runtime using CryptoRngCore
        REF_CANARY.push(rng.next_u64());

        // TODO: use critical_write in future
        canary = REF_CANARY.peek();
    }

    helper::dsb();
    run();

    // SAFETY: Reading a global variable is safe because we do not have race-conditions
    critical_if(
        || unsafe { canary == REF_CANARY.pop() },
        || (),
        || secure_reset_device(),
    );
}
