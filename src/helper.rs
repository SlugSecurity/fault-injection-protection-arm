use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

/// DSB with compiler fence.
// https://github.com/rust-embedded/cortex-m/issues/308
#[inline(always)]
pub(crate) fn dsb() {
    compiler_fence(Ordering::SeqCst);

    // SAFETY: "dsb" is always safe.
    unsafe { asm!("dsb") }

    compiler_fence(Ordering::SeqCst);
}
