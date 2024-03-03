use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

/// DSB(Data Synchronization Barrier) with compiler fence.
#[inline(always)]
pub(crate) fn dsb() {
    compiler_fence(Ordering::SeqCst);

    // SAFETY: "dsb" is always safe.
    unsafe { asm!("dsb") }

    compiler_fence(Ordering::SeqCst);
}
