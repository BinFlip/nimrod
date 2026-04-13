#![no_main]

use libfuzzer_sys::fuzz_target;
use nimrod::demangle::{identifier, modpath, symbol};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let _ = identifier::demangle(s);
    let _ = identifier::mangle(s);
    let _ = symbol::parse(s);
    let _ = modpath::decode(s);

    // Round-trip: mangle then demangle should not panic.
    let mangled = identifier::mangle(s);
    let _ = identifier::demangle(&mangled);
});
