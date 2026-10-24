use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountAllocations;

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

fn record_allocation() {
    let _ = ALLOCATIONS.try_with(|count| {
        if let Some(current) = count.get() {
            count.set(Some(current + 1));
        }
    });
}

unsafe impl GlobalAlloc for CountAllocations {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountAllocations = CountAllocations;

#[derive(jce::JceStruct)]
struct Known {
    #[jce(tag = "2", required)]
    answer: i32,
}

#[test]
fn unmatched_nested_fields_do_not_allocate_or_interpret_opaque_bytes() {
    use jce::JceStruct;
    let wire = [
        0x1a, // unknown struct
        0xf8, 200, 0, 1, // extended-tag map, one entry
        6, 3, 0xff, 0, 0x0e, // opaque key need not be UTF-8 when skipped
        0x19, 0, 2, // list value
        0x0d, 0, 0, 3, 0xff, 0x80, 0x0e, // byte list
        0x0a, 0x0c, 0x0b, // nested structure
        0x0b, 0x20, 42,
    ];
    ALLOCATIONS.with(|count| count.set(Some(0)));
    let result = Known::decode(&wire[..]);
    let allocations = ALLOCATIONS.with(|count| count.replace(None).unwrap());
    assert_eq!(result.unwrap().answer, 42);
    assert_eq!(allocations, 0);
}
