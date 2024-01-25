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

/// ISB(Instruction Synchronization Barrier) with compiler fence.
#[inline(always)]
pub(crate) fn isb() {
    // no re-ordering of reads and writes across this point is allowed
    compiler_fence(Ordering::SeqCst);

    // SAFETY: "isb" is always safe.
    unsafe { asm!("isb") }

    compiler_fence(Ordering::SeqCst);
}
