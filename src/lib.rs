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
            secure_reset_device();
        }

        // SAFETY: cond is non-null and properly aligned since it comes from a
        // Rust variable. In addition SecureBool derives the Copy trait, so a
        // bit-wise copy is performed
        unsafe {
            write_volatile(&mut cond, SecureBool::True);
        }
    }

    helper::dsb();
    secure_random_delay();

    if black_box(black_box(condition()) == SecureBool::False) {
        if black_box(black_box(condition()) == SecureBool::True) {
            secure_reset_device();
        }

        // SAFETY: cond is non-null, properly aligned, and initialized since it comes from a Rust variable.
        if unsafe { read_volatile(&cond) != SecureBool::False } {
            secure_reset_device();
        }

        // Not moving the parentheses to the outside makes smaller code.
        #[allow(clippy::unit_arg)]
        black_box(failure());
    } else {
        if black_box(black_box(condition()) == SecureBool::False) {
            secure_reset_device();
        }

        // SAFETY: cond is non-null, properly aligned, and initialized since it comes from a Rust variable.
        if unsafe { read_volatile(&cond) != SecureBool::True } {
            secure_reset_device();
        }

        // Not moving the parentheses to the outside makes smaller code.
        #[allow(clippy::unit_arg)]
        black_box(success());
    }

    helper::dsb();
}

/// Compares two byte arrays in constant time, regardless of the size or
/// content of the inputs
pub fn const_time_comp<const T: usize>(a: &[u8; T], b: &[u8; T]) -> SecureBool {
    todo!()
}
