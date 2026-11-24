//! Little helpers shared by the FAT, exFAT and partition code: bounds-checked little-endian reads,
//! DOS timestamps, the OEM (code page 437) character set.

use std::sync::OnceLock;

pub(crate) fn rd16(b: &[u8], o: usize) -> u16 {
    match b.get(o..o + 2) {
        Some(s) => u16::from_le_bytes([s[0], s[1]]),
        None => 0,
    }
}

pub(crate) fn rd32(b: &[u8], o: usize) -> u32 {
    match b.get(o..o + 4) {
        Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}

pub(crate) fn rd64(b: &[u8], o: usize) -> u64 {
    match b.get(o..o + 8) {
        Some(s) => {
            let mut a = [0u8; 8];
            a.copy_from_slice(s);
            u64::from_le_bytes(a)
        }
        None => 0,
    }
}

/// The PC's current offset from UTC in milliseconds (local = UTC + offset). FAT stores local time
/// without a zone, so timestamps are converted assuming the volume was written in the same zone and
/// daylight-saving state the PC is in now (an approximation the UI should not present as exact).
pub(crate) fn local_offset_ms() -> i64 {
    static OFF: OnceLock<i64> = OnceLock::new();
    *OFF.get_or_init(query_local_offset_ms)
}

#[cfg(windows)]
fn query_local_offset_ms() -> i64 {
    use windows_sys::Win32::Foundation::FILETIME;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemTimeAsFileTime(ft: *mut FILETIME);
        fn FileTimeToLocalFileTime(ft: *const FILETIME, local: *mut FILETIME) -> i32;
    }
    let mut utc = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut local = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    // SAFETY: both pointers refer to valid, writable FILETIME values on the stack.
    let ok = unsafe {
        GetSystemTimeAsFileTime(&mut utc);
        FileTimeToLocalFileTime(&utc, &mut local)
    };
    if ok == 0 {
        return 0;
    }
    let u = ((utc.dwHighDateTime as u64) << 32 | utc.dwLowDateTime as u64) as i64;
    let l = ((local.dwHighDateTime as u64) << 32 | local.dwLowDateTime as u64) as i64;
    // 100 ns ticks -> ms, rounded to whole minutes.
    let ms = (l - u) / 10_000;
    (ms as f64 / 60_000.0).round() as i64 * 60_000
}

#[cfg(not(windows))]
fn query_local_offset_ms() -> i64 {
    0
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A DOS date/time (as wall-clock time) to Unix ms, then shifted by `-offset_ms` to UTC.
/// `extra_ms` adds sub-second precision (FAT "tenths" field, exFAT 10 ms increments).
/// Returns None for a zero or invalid date.
pub(crate) fn dos_to_ms(date: u16, time: u16, extra_ms: i64, offset_ms: i64) -> Option<i64> {
    if date == 0 {
        return None;
    }
    let year = 1980 + (date >> 9) as i64;
    let month = ((date >> 5) & 0x0F) as u32;
    let day = (date & 0x1F) as u32;
    if !(1..=12).contains(&month) || day == 0 || day > 31 {
        return None;
    }
    let hour = (time >> 11) as i64;
    let min = ((time >> 5) & 0x3F) as i64;
    let sec = ((time & 0x1F) * 2) as i64;
    if hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let wall = ((days * 24 + hour) * 60 + min) * 60_000 + sec * 1000 + extra_ms.clamp(0, 1990);
    Some(wall - offset_ms)
}

/// Code page 437 upper half (0x80..0xFF), the usual OEM code page of FAT short names.
const CP437_HI: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";

pub(crate) fn oem_char(b: u8) -> char {
    if b < 0x80 {
        return b as char;
    }
    CP437_HI.chars().nth((b - 0x80) as usize).unwrap_or('_')
}

/// UTF-16 code units to a String (stops at the first NUL; lone surrogates become U+FFFD).
pub(crate) fn utf16_until_nul(units: &[u16]) -> String {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_dates_convert() {
        // 2024-02-29 13:45:58 wall clock, no offset.
        let date = ((2024 - 1980) << 9 | 2 << 5 | 29) as u16;
        let time = (13 << 11 | 45 << 5 | 29) as u16;
        let ms = dos_to_ms(date, time, 0, 0).unwrap();
        assert_eq!(ms, 1_709_214_358_000);
        assert_eq!(dos_to_ms(date, time, 0, 3_600_000).unwrap(), ms - 3_600_000);
        assert_eq!(dos_to_ms(0, 0, 0, 0), None);
        assert_eq!(dos_to_ms(13 << 5 | 1, 0, 0, 0), None);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn oem_and_reads() {
        assert_eq!(oem_char(b'A'), 'A');
        assert_eq!(oem_char(0x82), 'é');
        assert_eq!(oem_char(0xFF), '\u{a0}');
        assert_eq!(CP437_HI.chars().count(), 128);
        assert_eq!(rd32(&[1, 0], 0), 0);
        assert_eq!(rd16(&[1, 2], 0), 0x0201);
    }
}
