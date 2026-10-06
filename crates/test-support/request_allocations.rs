//! Thread-local allocation accounting for synchronous request-encoding regressions.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;
thread_local! {
    static ALLOCATED: Cell<Option<usize>> = const { Cell::new(None) };
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn record(bytes: usize) {
    ALLOCATED.with(|count| {
        if let Some(total) = count.get() {
            count.set(Some(total + bytes));
        }
    });
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
    }
}

/// Measure allocation requests on this thread while `operation` runs.
pub fn allocated<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALLOCATED.with(|count| count.set(None));
        }
    }
    ALLOCATED.with(|count| {
        assert!(
            count.get().is_none(),
            "allocation measurements must not nest"
        );
        count.set(Some(0));
    });
    let reset = Reset;
    let result = operation();
    let bytes = ALLOCATED.with(|count| count.get().unwrap());
    drop(reset);
    (result, bytes)
}
