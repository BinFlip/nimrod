//! Exception raise-site recovery (phase 2).
//!
//! Recovers full `(exception_type, proc_name, file, line)` tuples by
//! locating calls to `raiseExceptionEx` in the `.text` section and
//! parsing the argument-loading instructions preceding each call.
//!
//! ## Calling convention
//!
//! `raiseExceptionEx(e, ename, procname, filename, line)`:
//!
//! | Arg  | x86_64 SysV | AArch64 | Content              |
//! |------|-------------|---------|----------------------|
//! | e    | RDI / x0    | x0      | Exception object ptr |
//! | ename| RSI / x1    | x1      | Type name cstring    |
//! | proc | RDX / x2    | x2      | Proc name cstring    |
//! | file | RCX / x3    | x3      | File path cstring    |
//! | line | R8  / x4    | x4      | Line number (int)    |
//!
//! ## Supported architectures
//!
//! - **x86_64**: scans for `e8` (near call) with displacement targeting
//!   `raiseExceptionEx`, then matches `lea <disp>(%rip), %rXX` and
//!   `mov $imm, %r8d` in a backward window.
//! - **AArch64**: scans for `bl` targeting `raiseExceptionEx`, then matches
//!   `adrp`+`add` pairs for string arguments and `mov`/`movz` for line.

use crate::{
    container::{Arch, Container, SectionKind},
    rtti::v2::read_cstring_at_va,
    util,
};

/// A fully recovered raise site.
#[derive(Debug, Clone)]
pub struct RaiseSite {
    /// Virtual address of the call instruction.
    pub call_addr: u64,
    /// Exception type name (e.g. `"ValueError"`).
    pub exception_type: Option<String>,
    /// Enclosing proc name (from instruction analysis).
    pub proc_name: Option<String>,
    /// Source file path (from instruction analysis).
    pub file: Option<String>,
    /// Source line number.
    pub line: Option<u32>,
    /// Enclosing function symbol (from symbol table VA lookup).
    /// This is recovered independently of instruction analysis and
    /// provides the mangled/demangled function name even when the
    /// proc_name argument wasn't recovered.
    pub enclosing_function: Option<String>,
}

/// Scans the binary for `raiseExceptionEx` call sites and recovers
/// the argument tuples.
///
/// After instruction-level recovery, each site is enriched with the
/// enclosing function name from the symbol table (independent of
/// whether the instruction analysis found the proc_name argument).
pub fn scan(container: &Container<'_>) -> Vec<RaiseSite> {
    // Find the raiseExceptionEx symbol(s).
    let targets = find_raise_targets(container);
    if targets.is_empty() {
        return Vec::new();
    }

    let mut sites = match container.arch() {
        Arch::Amd64 => scan_x86_64(container, &targets),
        Arch::Aarch64 => scan_aarch64(container, &targets),
        _ => return Vec::new(),
    };

    // Enrich each site with the enclosing function from the symbol table.
    for site in &mut sites {
        if let Some(func) = container.function_at_va(site.call_addr) {
            site.enclosing_function = Some(func.name.to_string());
        }
    }

    sites
}

/// Returns the virtual addresses of `raiseExceptionEx` (and variants
/// like `raiseExceptionEx.constprop.0`).
fn find_raise_targets(container: &Container<'_>) -> Vec<u64> {
    container
        .symbols()
        .iter()
        .filter(|s| {
            let name = s.name.as_ref();
            name == "raiseExceptionEx" || name.starts_with("raiseExceptionEx.")
        })
        .map(|s| s.vm_addr)
        .collect()
}

/// How far backwards from a call site to scan for argument loads.
const X86_BACKWARD_WINDOW: usize = 80;

fn scan_x86_64(container: &Container<'_>, targets: &[u64]) -> Vec<RaiseSite> {
    let mut sites = Vec::new();
    let bytes = container.bytes();

    for section in container.sections() {
        if section.kind != SectionKind::Text {
            continue;
        }
        if section.data.len() < 5 {
            continue;
        }

        let sec_data = section.data;
        let sec_va = section.vm_addr;

        // Scan for `e8 XX XX XX XX` (near call with 32-bit displacement).
        let mut i = 0;
        while i + 5 <= sec_data.len() {
            if sec_data[i] == 0xe8 {
                let disp = i32::from_le_bytes([
                    sec_data[i + 1],
                    sec_data[i + 2],
                    sec_data[i + 3],
                    sec_data[i + 4],
                ]);
                let call_va = sec_va + i as u64;
                let target_va = (call_va as i64 + 5 + disp as i64) as u64;

                if targets.contains(&target_va) {
                    let site = recover_args_x86_64(container, bytes, sec_data, i, call_va);
                    sites.push(site);
                }
            }
            i += 1;
        }
    }

    sites
}

/// Walks backwards from a call site to find argument-loading instructions.
///
/// Patterns matched:
/// - `48 8d 35 <disp32>` → `lea <disp>(%rip), %rsi` (ename)
/// - `48 8d 15 <disp32>` → `lea <disp>(%rip), %rdx` (procname)
/// - `48 8d 0d <disp32>` → `lea <disp>(%rip), %rcx` (filename)
/// - `41 b8 <imm32>`     → `mov $imm32, %r8d`       (line)
fn recover_args_x86_64(
    container: &Container<'_>,
    bytes: &[u8],
    sec_data: &[u8],
    call_offset: usize,
    call_va: u64,
) -> RaiseSite {
    let start = call_offset.saturating_sub(X86_BACKWARD_WINDOW);
    let window = &sec_data[start..call_offset];

    let mut etype_va: Option<u64> = None;
    let mut proc_va: Option<u64> = None;
    let mut file_va: Option<u64> = None;
    let mut line: Option<u32> = None;

    // Scan the window for known instruction patterns.
    let mut j = 0;
    while j + 7 <= window.len() {
        let abs_off = start + j;

        // 7-byte LEA with RIP-relative displacement: 48 8d XX <disp32>
        if window[j] == 0x48 && window[j + 1] == 0x8d && j + 7 <= window.len() {
            let modrm = window[j + 2];
            let disp =
                i32::from_le_bytes([window[j + 3], window[j + 4], window[j + 5], window[j + 6]]);
            // RIP at end of this instruction = section_va + abs_off + 7
            let insn_va = call_va.wrapping_sub(call_offset.wrapping_sub(abs_off) as u64);
            let target = (insn_va as i64).wrapping_add(7).wrapping_add(disp as i64) as u64;

            match modrm {
                0x35 => etype_va = Some(target), // lea ..., %rsi
                0x15 => proc_va = Some(target),  // lea ..., %rdx
                0x0d => file_va = Some(target),  // lea ..., %rcx
                _ => {}
            }
            j += 7;
            continue;
        }

        // 6-byte MOV imm32 to R8D: 41 b8 <imm32>
        if window[j] == 0x41 && window[j + 1] == 0xb8 && j + 6 <= window.len() {
            let imm =
                u32::from_le_bytes([window[j + 2], window[j + 3], window[j + 4], window[j + 5]]);
            // Sanity: line numbers are typically < 100_000
            if imm < 100_000 {
                line = Some(imm);
            }
            j += 6;
            continue;
        }

        j += 1;
    }

    RaiseSite {
        call_addr: call_va,
        exception_type: etype_va.and_then(|va| read_cstring_at_va(container, bytes, va)),
        proc_name: proc_va.and_then(|va| read_cstring_at_va(container, bytes, va)),
        file: file_va.and_then(|va| read_cstring_at_va(container, bytes, va)),
        line,
        enclosing_function: None, // populated by scan() after instruction recovery
    }
}

/// How far backwards (in bytes) from a call site to scan on AArch64.
const AARCH64_BACKWARD_WINDOW: usize = 128;

fn scan_aarch64(container: &Container<'_>, targets: &[u64]) -> Vec<RaiseSite> {
    let mut sites = Vec::new();
    let bytes = container.bytes();

    for section in container.sections() {
        if section.kind != SectionKind::Text {
            continue;
        }
        if section.data.len() < 4 {
            continue;
        }

        let sec_data = section.data;
        let sec_va = section.vm_addr;

        // AArch64 instructions are 4 bytes, aligned.
        let mut i = 0;
        while i + 4 <= sec_data.len() {
            let insn = util::read_u32_le(sec_data, i);

            // BL instruction: 1001 01ii iiii iiii iiii iiii iiii iiii
            if insn & 0xFC00_0000 == 0x9400_0000 {
                let imm26 = (insn & 0x03FF_FFFF) as i32;
                // Sign-extend 26-bit immediate.
                let offset = if imm26 & (1 << 25) != 0 {
                    (imm26 | !0x03FF_FFFF) as i64 * 4
                } else {
                    imm26 as i64 * 4
                };
                let call_va = sec_va + i as u64;
                let target_va = (call_va as i64 + offset) as u64;

                if targets.contains(&target_va) {
                    let site = recover_args_aarch64(container, bytes, sec_data, i, call_va);
                    sites.push(site);
                }
            }

            i += 4; // AArch64 instructions are fixed 4 bytes
        }
    }

    sites
}

/// Walks backwards from a BL to find ADRP+ADD pairs loading string
/// addresses into x1–x3, and MOV/MOVZ loading line into x4/w4.
fn recover_args_aarch64(
    container: &Container<'_>,
    bytes: &[u8],
    sec_data: &[u8],
    call_offset: usize,
    call_va: u64,
) -> RaiseSite {
    let start = call_offset.saturating_sub(AARCH64_BACKWARD_WINDOW);
    // Align start to 4 bytes.
    let start = start & !3;

    // Collect ADRP results: reg -> page_base
    let mut adrp_pages: [Option<u64>; 32] = [None; 32];
    // Collect final register values: x1=etype, x2=proc, x3=file, x4/w4=line
    let mut reg_vals: [Option<u64>; 32] = [None; 32];
    let mut line: Option<u32> = None;

    let mut j = start;
    while j < call_offset {
        let insn = util::read_u32_le(sec_data, j);
        let insn_va = call_va - (call_offset - j) as u64;

        // ADRP Xd, <page>: 1ii1 0000 iiii iiii iiii iiii iiid dddd
        if insn & 0x9F00_0000 == 0x9000_0000 {
            let rd = (insn & 0x1F) as usize;
            let immhi = ((insn >> 5) & 0x7FFFF) as i64;
            let immlo = ((insn >> 29) & 0x3) as i64;
            let imm = (immhi << 2) | immlo;
            // Sign-extend 21-bit immediate.
            let imm = if imm & (1 << 20) != 0 {
                imm | !0x1FFFFF
            } else {
                imm
            };
            let page = ((insn_va as i64) & !0xFFF) + (imm << 12);
            adrp_pages[rd] = Some(page as u64);
        }

        // ADD Xd, Xn, #imm12: 1001 0001 00ii iiii iiii iinn nnnd dddd
        if insn & 0xFFC0_0000 == 0x9100_0000 {
            let rd = (insn & 0x1F) as usize;
            let rn = ((insn >> 5) & 0x1F) as usize;
            let imm12 = ((insn >> 10) & 0xFFF) as u64;
            if let Some(page) = adrp_pages[rn] {
                reg_vals[rd] = Some(page + imm12);
            }
        }

        // MOVZ Wd, #imm16: 0101 0010 100i iiii iiii iiii iiid dddd
        if insn & 0xFFE0_0000 == 0x5280_0000 {
            let rd = (insn & 0x1F) as usize;
            let imm16 = (insn >> 5) & 0xFFFF;
            if rd == 4 && imm16 < 100_000 {
                line = Some(imm16);
            }
            reg_vals[rd] = Some(imm16 as u64);
        }

        // MOV Xd, Xm (alias for ORR Xd, XZR, Xm): 1010 1010 000m mmmm 0000 0011 111d dddd
        if insn & 0xFFE0_FFE0 == 0xAA00_03E0 {
            let rd = (insn & 0x1F) as usize;
            let rm = ((insn >> 16) & 0x1F) as usize;
            if let Some(val) = reg_vals[rm] {
                reg_vals[rd] = Some(val);
            }
        }

        j += 4;
    }

    // x1 = etype, x2 = proc, x3 = file
    let etype_va = reg_vals[1];
    let proc_va = reg_vals[2];
    let file_va = reg_vals[3];

    RaiseSite {
        call_addr: call_va,
        exception_type: etype_va.and_then(|va| read_cstring_at_va(container, bytes, va)),
        proc_name: proc_va.and_then(|va| read_cstring_at_va(container, bytes, va)),
        file: file_va.and_then(|va| read_cstring_at_va(container, bytes, va)),
        line,
        enclosing_function: None, // populated by scan() after instruction recovery
    }
}
