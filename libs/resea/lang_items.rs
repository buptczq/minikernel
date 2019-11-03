#[cfg(not(test))]
use core::panic;
#[cfg(not(test))]
use core::alloc::Layout;

#[lang="eh_personality"]
#[no_mangle]
#[cfg(not(test))]
pub fn eh_personality() {
    loop {}
}

#[panic_handler]
#[no_mangle]
#[cfg(not(test))]
pub fn panic(info: &panic::PanicInfo) -> ! {
    error!("PANIC: {}", info);
    loop {}
}

#[alloc_error_handler]
#[cfg(not(test))]
fn alloc_error(_layout: Layout) -> ! {
    panic!("out of memory");
}
