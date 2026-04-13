#![no_main]

use libfuzzer_sys::fuzz_target;
use nimrod::NimBinary;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }

    let Ok(bin) = NimBinary::from_bytes(data) else {
        return;
    };

    let _ = bin.format();
    let _ = bin.arch();
    let _ = bin.detection_matches();

    if !bin.is_nim() {
        return;
    }

    let _ = bin.gc_mode();
    let _ = bin.nim_main_prefix();
    let _ = bin.entry_shims();
    let _ = bin.init_functions();
    let _ = bin.rtti_symbols();
    let _ = bin.exception_types();
    let _ = bin.stack_trace();
    let _ = bin.nimble_paths();
    let _ = bin.string_literals_v2();
    let _ = bin.string_literals_v1();
    let _ = bin.raise_sites();
    let _ = bin.module_map();
});
