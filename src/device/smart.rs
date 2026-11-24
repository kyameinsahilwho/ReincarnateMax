//! Drive health (SMART / NVMe health log / Windows storage reliability counters).
//! OWNER: device agent.
//!
//! Read-only routes only:
//! - NVMe: the health log page (0x02) through `IOCTL_STORAGE_QUERY_PROPERTY` with
//!   STORAGE_PROTOCOL_SPECIFIC_DATA (a FILE_ANY_ACCESS query: no write access needed).
//! - ATA: the SMART attribute and threshold tables through WMI (`root\WMI`
//!   MSStorageDriver_FailurePredictData / ...Thresholds; the disk driver issues SMART READ DATA itself).
//!   `SMART_RCV_DRIVE_DATA` would need a handle with write access, which MAX never opens.
//! - Windows: `MSFT_PhysicalDisk.HealthStatus` and `MSFT_StorageReliabilityCounter` (Storage WMI).

use super::list::{health_word, wmi};
use super::win;
use crate::util::is_elevated;
use serde::Serialize;

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct SmartInfo {
    pub disk: u32,
    /// Any health data could be read.
    pub available: bool,
    /// More detail is available when running as administrator.
    pub needs_admin: bool,
    /// "Healthy" | "Warning" | "Unhealthy" | "Unknown"
    pub health: String,
    pub temperature_c: Option<i32>,
    pub power_on_hours: Option<u64>,
    pub power_cycles: Option<u64>,
    /// NVMe "percentage used" (wear), 0-255.
    pub percent_used: Option<u32>,
    pub media_errors: Option<u64>,
    pub reallocated_sectors: Option<u64>,
    pub pending_sectors: Option<u64>,
    pub unsafe_shutdowns: Option<u64>,
    pub data_read: Option<u64>,
    pub data_written: Option<u64>,
    pub attributes: Vec<SmartAttr>,
    /// Plain sentences ("12 sectors are waiting to be remapped. Image this drive before scanning it.").
    pub warnings: Vec<String>,
    /// Where the numbers came from: "NVMe health log" | "ATA SMART" | "Windows storage reliability".
    pub source: String,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct SmartAttr {
    pub id: u32,
    pub name: String,
    pub current: u32,
    pub worst: u32,
    pub threshold: u32,
    pub raw: u64,
    /// "ok" | "warn" | "fail"
    pub status: String,
}

#[tauri::command]
pub async fn smart_info(disk: u32) -> Result<SmartInfo, String> {
    tauri::async_runtime::spawn_blocking(move || read(disk)).await.map_err(|_| "Reading the drive's health stopped unexpectedly.".to_string())?
}

const STORAGE_NS: &str = r"ROOT\Microsoft\Windows\Storage";
const IMAGE_FIRST: &str = "Make a disk image before scanning this drive.";

fn read(disk: u32) -> Result<SmartInfo, String> {
    let elevated = is_elevated();
    let h = win::open_query(&format!(r"\\.\PhysicalDrive{disk}")).ok_or_else(|| "That disk isn't connected anymore. Refresh the drive list.".to_string())?;
    let bus = win::device_descriptor(&h).map(|d| d.bus_type).unwrap_or(0);
    let mut info = SmartInfo { disk, health: "Unknown".into(), ..Default::default() };

    // Windows' own view (WMI): health status, then the reliability counters (usually admin-only).
    let (health, rel) = windows_reliability(disk);
    if let Some(hw) = health {
        info.health = hw.into();
        info.available = true;
    }

    let mut detailed = false;
    if bus == 17 {
        let log = nvme_health_log(&h).or_else(|| if elevated { win::open_device(&format!(r"\\.\PhysicalDrive{disk}"), win::GENERIC_READ, 0).ok().and_then(|g| nvme_health_log(&g)) } else { None });
        if let Some(log) = log {
            apply_nvme(&mut info, &parse_nvme_health(&log));
            detailed = true;
        }
    } else if elevated {
        if let Some((data, thresholds)) = ata_smart_wmi(disk) {
            let attrs = parse_ata_attributes(&data, thresholds.as_deref());
            if !attrs.is_empty() {
                apply_ata(&mut info, attrs);
                detailed = true;
            }
        }
    }
    if let Some(r) = rel {
        let any = r.temperature.is_some() || r.wear.is_some() || r.power_on_hours.is_some() || r.read_errors.is_some();
        if any && !detailed {
            info.source = "Windows storage reliability".into();
        }
        info.temperature_c = info.temperature_c.or(r.temperature);
        info.percent_used = info.percent_used.or(r.wear);
        info.power_on_hours = info.power_on_hours.or(r.power_on_hours);
        info.power_cycles = info.power_cycles.or(r.start_stop);
        if info.media_errors.is_none() {
            info.media_errors = r.read_errors.filter(|_| !detailed);
        }
        detailed |= any;
    }
    info.available |= detailed;
    info.needs_admin = !elevated && !detailed;
    finish(&mut info);
    Ok(info)
}

// ---------------------------------------------------------------------------- Windows / WMI

#[derive(Default, Debug)]
struct Reliability {
    temperature: Option<i32>,
    wear: Option<u32>,
    power_on_hours: Option<u64>,
    start_stop: Option<u64>,
    read_errors: Option<u64>,
}

/// MSFT_PhysicalDisk.HealthStatus + its MSFT_StorageReliabilityCounter (the latter needs admin
/// rights on most systems; failure just leaves it None).
fn windows_reliability(disk: u32) -> (Option<&'static str>, Option<Reliability>) {
    wmi::with(STORAGE_NS, move |w| {
        let Ok(pds) = w.rows(&format!("SELECT ObjectId, DeviceId, HealthStatus FROM MSFT_PhysicalDisk WHERE DeviceId = '{disk}'"), &["HealthStatus", "__RELPATH"]) else {
            return (None, None);
        };
        let Some(pd) = pds.first() else { return (None, None) };
        let health = health_word(pd.get("HealthStatus").u32());
        let rel = pd.get("__RELPATH").string().and_then(|path| {
            let rows = w
                .rows(
                    &format!("ASSOCIATORS OF {{{path}}} WHERE ResultClass = MSFT_StorageReliabilityCounter"),
                    &["Temperature", "Wear", "PowerOnHours", "StartStopCycleCount", "ReadErrorsTotal", "ReadErrorsUncorrected"],
                )
                .ok()?;
            let c = rows.first()?;
            Some(Reliability {
                temperature: c.get("Temperature").int().filter(|&t| t > 0 && t < 200).map(|t| t as i32),
                wear: c.get("Wear").u32(),
                power_on_hours: c.get("PowerOnHours").u64(),
                start_stop: c.get("StartStopCycleCount").u64(),
                read_errors: c.get("ReadErrorsUncorrected").u64().or_else(|| c.get("ReadErrorsTotal").u64()),
            })
        });
        (health, rel)
    })
    .unwrap_or((None, None))
}

/// ATA SMART data + thresholds (512-byte tables) through root\WMI, matched to the disk number via
/// Win32_DiskDrive.PNPDeviceID (= InstanceName without its "_0" suffix).
fn ata_smart_wmi(disk: u32) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    let drives = wmi::query(r"ROOT\CIMV2", &format!("SELECT Index, PNPDeviceID FROM Win32_DiskDrive WHERE Index = {disk}"), &["PNPDeviceID"]).ok()?;
    let pnp = drives.first()?.get("PNPDeviceID").string()?.to_ascii_lowercase();
    let find = |class: &str| -> Option<Vec<u8>> {
        let rows = wmi::query(r"ROOT\WMI", &format!("SELECT InstanceName, VendorSpecific FROM {class}"), &["InstanceName", "VendorSpecific"]).ok()?;
        rows.iter().find(|r| r.get("InstanceName").string().is_some_and(|i| i.to_ascii_lowercase().starts_with(&pnp))).and_then(|r| r.get("VendorSpecific").bytes())
    };
    let data = find("MSStorageDriver_FailurePredictData")?;
    Some((data, find("MSStorageDriver_FailurePredictThresholds")))
}

// ------------------------------------------------------------------------------------- NVMe

/// NVMe health information log (page 0x02, 512 bytes) via the storage protocol-specific query.
fn nvme_health_log(h: &win::Handle) -> Option<Vec<u8>> {
    const HDR: usize = 8; // STORAGE_PROPERTY_QUERY up to AdditionalParameters
    const SPEC: usize = 40; // STORAGE_PROTOCOL_SPECIFIC_DATA
    const LOG: usize = 512;
    for property in [50u32 /* StorageDeviceProtocolSpecificProperty */, 49 /* StorageAdapterProtocolSpecificProperty */] {
        let mut b = vec![0u8; HDR + SPEC + LOG];
        b[0..4].copy_from_slice(&property.to_le_bytes());
        let fields: [u32; 6] = [
            3,           // ProtocolTypeNvme
            2,           // NVMeDataTypeLogPage
            0x02,        // health information log
            0,           // offset low
            SPEC as u32, // ProtocolDataOffset (from the start of STORAGE_PROTOCOL_SPECIFIC_DATA)
            LOG as u32,  // ProtocolDataLength
        ];
        for (i, f) in fields.iter().enumerate() {
            b[HDR + i * 4..HDR + i * 4 + 4].copy_from_slice(&f.to_le_bytes());
        }
        let input = b.clone();
        let Ok(n) = win::ioctl(h, win::IOCTL_STORAGE_QUERY_PROPERTY, &input, &mut b) else { continue };
        // Output: STORAGE_PROTOCOL_DATA_DESCRIPTOR { Version, Size, ProtocolSpecificData }.
        if n < HDR + SPEC || win::le_u32(&b, 0) as usize != HDR + SPEC {
            continue;
        }
        let off = HDR + win::le_u32(&b, HDR + 16) as usize;
        let len = win::le_u32(&b, HDR + 20) as usize;
        if len >= LOG && off + LOG <= b.len() {
            return Some(b[off..off + LOG].to_vec());
        }
    }
    None
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct NvmeHealth {
    pub critical_warning: u8,
    pub temperature_c: i32,
    pub available_spare: u8,
    pub spare_threshold: u8,
    pub percent_used: u8,
    pub data_read: u128,
    pub data_written: u128,
    pub power_cycles: u128,
    pub power_on_hours: u128,
    pub unsafe_shutdowns: u128,
    pub media_errors: u128,
}

fn le128(b: &[u8], o: usize) -> u128 {
    u128::from_le_bytes(b[o..o + 16].try_into().unwrap())
}

/// NVME_HEALTH_INFO_LOG (NVMe base spec, Get Log Page 02h).
pub(crate) fn parse_nvme_health(b: &[u8]) -> NvmeHealth {
    if b.len() < 192 {
        return NvmeHealth::default();
    }
    let kelvin = u16::from_le_bytes([b[1], b[2]]) as i32;
    NvmeHealth {
        critical_warning: b[0],
        temperature_c: if kelvin > 0 { kelvin - 273 } else { 0 },
        available_spare: b[3],
        spare_threshold: b[4],
        percent_used: b[5],
        // Data units are thousands of 512-byte units.
        data_read: le128(b, 32) * 512_000,
        data_written: le128(b, 48) * 512_000,
        power_cycles: le128(b, 112),
        power_on_hours: le128(b, 128),
        unsafe_shutdowns: le128(b, 144),
        media_errors: le128(b, 160),
    }
}

fn sat(v: u128) -> u64 {
    v.min(u64::MAX as u128) as u64
}

fn apply_nvme(info: &mut SmartInfo, n: &NvmeHealth) {
    info.source = "NVMe health log".into();
    info.temperature_c = (n.temperature_c > -40 && n.temperature_c < 200 && n.temperature_c != 0).then_some(n.temperature_c);
    info.percent_used = Some(n.percent_used as u32);
    info.data_read = Some(sat(n.data_read));
    info.data_written = Some(sat(n.data_written));
    info.power_cycles = Some(sat(n.power_cycles));
    info.power_on_hours = Some(sat(n.power_on_hours));
    info.unsafe_shutdowns = Some(sat(n.unsafe_shutdowns));
    info.media_errors = Some(sat(n.media_errors));
    let w = &mut info.warnings;
    let cw = n.critical_warning;
    if cw & 0x01 != 0 {
        w.push(format!("The drive's spare blocks are almost used up ({}% left). {IMAGE_FIRST}", n.available_spare));
    }
    if cw & 0x02 != 0 {
        w.push("The drive reports a temperature problem. Let it cool down before a long scan.".into());
    }
    if cw & 0x04 != 0 {
        w.push(format!("The drive reports that its reliability is degraded. {IMAGE_FIRST}"));
    }
    if cw & 0x08 != 0 {
        w.push("The drive has switched itself to read-only to protect your data. Copy your files off it soon.".into());
    }
    if cw & 0x10 != 0 {
        w.push("The drive's power-loss protection has failed. Avoid unplugging it while it is busy.".into());
    }
    if n.media_errors > 0 {
        w.push(format!("The drive has reported {} unreadable data errors. {IMAGE_FIRST}", n.media_errors));
    }
    if n.percent_used >= 100 {
        w.push(format!("The drive has used up its rated write endurance. {IMAGE_FIRST}"));
    }
    if cw & 0x0D != 0 || n.media_errors > 0 {
        info.health = "Unhealthy".into();
    } else if (cw != 0 || n.percent_used >= 90) && info.health != "Unhealthy" {
        info.health = "Warning".into();
    } else if info.health == "Unknown" {
        info.health = "Healthy".into();
    }
}

// -------------------------------------------------------------------------------------- ATA

pub(crate) fn attr_name(id: u8) -> &'static str {
    match id {
        1 => "Read error rate",
        2 => "Throughput performance",
        3 => "Spin-up time",
        4 => "Start/stop count",
        5 => "Reallocated sectors",
        7 => "Seek error rate",
        8 => "Seek time performance",
        9 => "Power-on hours",
        10 => "Spin retry count",
        11 => "Calibration retries",
        12 => "Power cycles",
        13 => "Soft read error rate",
        170 => "Available reserved space",
        171 => "Program fail count",
        172 => "Erase fail count",
        173 => "Wear leveling count",
        174 => "Unexpected power loss",
        177 => "Wear range delta",
        179 => "Used reserved blocks",
        180 => "Unused reserved blocks",
        181 => "Program fail count",
        182 => "Erase fail count",
        183 => "SATA downshift errors",
        184 => "End-to-end errors",
        187 => "Reported uncorrectable errors",
        188 => "Command timeouts",
        189 => "High fly writes",
        190 => "Airflow temperature",
        191 => "G-sense errors",
        192 => "Power-off retracts",
        193 => "Load cycles",
        194 => "Temperature",
        195 => "Hardware ECC recovered",
        196 => "Reallocation events",
        197 => "Pending sectors",
        198 => "Offline uncorrectable sectors",
        199 => "Interface CRC errors",
        200 => "Write error rate",
        202 => "Data address mark errors",
        231 => "SSD life left",
        232 => "Available reserved space",
        233 => "Media wearout indicator",
        234 => "Average erase count",
        235 => "Good block count",
        240 => "Head flying hours",
        241 => "Total LBAs written",
        242 => "Total LBAs read",
        _ => "Vendor specific",
    }
}

/// The 30 × 12-byte attribute table of SMART READ DATA (+ the thresholds table if given).
pub(crate) fn parse_ata_attributes(data: &[u8], thresholds: Option<&[u8]>) -> Vec<SmartAttr> {
    let mut out = Vec::new();
    for i in 0..30 {
        let o = 2 + i * 12;
        if o + 12 > data.len() {
            break;
        }
        let e = &data[o..o + 12];
        let id = e[0];
        if id == 0 {
            continue;
        }
        let raw = e[5..11].iter().rev().fold(0u64, |a, &b| a << 8 | b as u64);
        let threshold = thresholds
            .and_then(|t| (0..30).map(|k| 2 + k * 12).filter(|&k| k + 2 <= t.len()).find(|&k| t[k] == id).map(|k| t[k + 1]))
            .unwrap_or(0);
        let (current, worst) = (e[3] as u32, e[4] as u32);
        let raw = match id {
            194 | 190 => raw & 0xFF,             // temperature: low byte (others hold min/max)
            9 => raw & 0xFFFF_FFFF,              // some drives keep minutes in the high bytes
            5 | 196 | 197 | 198 => raw & 0xFFFF_FFFF,
            _ => raw,
        };
        let status = if threshold > 0 && current > 0 && current <= threshold as u32 {
            "fail"
        } else if matches!(id, 5 | 196 | 197 | 198 | 187 | 199) && raw > 0 {
            "warn"
        } else {
            "ok"
        };
        out.push(SmartAttr { id: id as u32, name: attr_name(id).into(), current, worst, threshold: threshold as u32, raw, status: status.into() });
    }
    out
}

fn apply_ata(info: &mut SmartInfo, attrs: Vec<SmartAttr>) {
    info.source = "ATA SMART".into();
    let raw = |id: u32| attrs.iter().find(|a| a.id == id).map(|a| a.raw);
    info.temperature_c = raw(194).or(raw(190)).filter(|&t| t > 0 && t < 150).map(|t| t as i32);
    info.power_on_hours = raw(9);
    info.power_cycles = raw(12);
    info.reallocated_sectors = raw(5);
    info.pending_sectors = raw(197);
    info.unsafe_shutdowns = raw(192).or(raw(174));
    info.media_errors = raw(187).or(raw(198));
    // Wear: 231 "life left" / 233 "media wearout" normalised values count down from 100.
    info.percent_used = attrs.iter().find(|a| matches!(a.id, 231 | 233 | 202) && a.current <= 100).map(|a| 100 - a.current);
    let failing = raw(5).unwrap_or(0) + raw(197).unwrap_or(0) + raw(198).unwrap_or(0);
    if failing > 0 {
        let what = if failing == 1 { "1 sector is".to_string() } else { format!("{failing} sectors are") };
        info.warnings.push(format!("{what} failing. {IMAGE_FIRST}"));
    }
    if let Some(c) = raw(199).filter(|&c| c > 0) {
        info.warnings.push(format!("The connection to the drive has had {c} transfer errors. Check or replace its cable."));
    }
    let failed: Vec<&SmartAttr> = attrs.iter().filter(|a| a.status == "fail").collect();
    for a in &failed {
        info.warnings.push(format!("The drive reports that it is failing ({}). {IMAGE_FIRST}", a.name.to_lowercase()));
    }
    if !failed.is_empty() || failing > 0 {
        info.health = if failed.is_empty() { "Warning" } else { "Unhealthy" }.into();
        if failing > 0 && raw(197).unwrap_or(0) + raw(198).unwrap_or(0) > 0 {
            info.health = "Unhealthy".into();
        }
    } else if info.health == "Unknown" {
        info.health = "Healthy".into();
    }
    info.attributes = attrs;
}

/// Shared closing touches: temperature sentence, Windows' own verdict.
fn finish(info: &mut SmartInfo) {
    if let Some(t) = info.temperature_c.filter(|&t| t >= 70) {
        info.warnings.push(format!("The drive is running hot ({t} °C). Let it cool down before a long scan."));
    }
    if info.health == "Unhealthy" && info.warnings.is_empty() {
        info.warnings.push(format!("Windows reports that this drive is unhealthy. {IMAGE_FIRST}"));
    }
    info.warnings.dedup();
}


#[cfg(test)]
mod tests {
    use super::*;

    fn nvme_sample() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0] = 0;
        b[1..3].copy_from_slice(&(273u16 + 41).to_le_bytes());
        b[3] = 100;
        b[4] = 10;
        b[5] = 3;
        b[32..48].copy_from_slice(&1_000u128.to_le_bytes()); // 1000 units = 512 MB
        b[48..64].copy_from_slice(&2_000u128.to_le_bytes());
        b[112..128].copy_from_slice(&1_234u128.to_le_bytes());
        b[128..144].copy_from_slice(&5_678u128.to_le_bytes());
        b[144..160].copy_from_slice(&42u128.to_le_bytes());
        b[160..176].copy_from_slice(&0u128.to_le_bytes());
        b
    }

    #[test]
    fn nvme_log_parses() {
        let n = parse_nvme_health(&nvme_sample());
        assert_eq!(n.temperature_c, 41);
        assert_eq!(n.percent_used, 3);
        assert_eq!(n.data_read, 512_000_000);
        assert_eq!(n.data_written, 1_024_000_000);
        assert_eq!((n.power_cycles, n.power_on_hours, n.unsafe_shutdowns, n.media_errors), (1234, 5678, 42, 0));
        let mut info = SmartInfo { health: "Unknown".into(), ..Default::default() };
        apply_nvme(&mut info, &n);
        finish(&mut info);
        assert_eq!(info.health, "Healthy");
        assert!(info.warnings.is_empty());
        assert_eq!(info.temperature_c, Some(41));

        let mut b = nvme_sample();
        b[0] = 0x04;
        b[1..3].copy_from_slice(&(273u16 + 75).to_le_bytes());
        b[160..176].copy_from_slice(&7u128.to_le_bytes());
        let mut info = SmartInfo { health: "Healthy".into(), ..Default::default() };
        apply_nvme(&mut info, &parse_nvme_health(&b));
        finish(&mut info);
        assert_eq!(info.health, "Unhealthy");
        assert_eq!(info.media_errors, Some(7));
        assert!(info.warnings.iter().any(|w| w.contains("7 unreadable") && w.ends_with(IMAGE_FIRST)), "{:?}", info.warnings);
        assert!(info.warnings.iter().any(|w| w.contains("75 °C")));
    }

    fn ata_entry(t: &mut [u8], slot: usize, id: u8, cur: u8, worst: u8, raw: u64) {
        let o = 2 + slot * 12;
        t[o] = id;
        t[o + 1] = 0x33;
        t[o + 3] = cur;
        t[o + 4] = worst;
        t[o + 5..o + 11].copy_from_slice(&raw.to_le_bytes()[..6]);
    }

    #[test]
    fn ata_attributes_parse() {
        let mut d = vec![0u8; 512];
        ata_entry(&mut d, 0, 5, 100, 100, 8);
        ata_entry(&mut d, 1, 9, 90, 90, 0x0012_0000_1F40); // 8000 hours, minutes in high bytes
        ata_entry(&mut d, 2, 12, 99, 99, 321);
        ata_entry(&mut d, 3, 194, 64, 50, 0x0032_0014_0024); // 36 °C, min 20, max 50
        ata_entry(&mut d, 4, 197, 100, 100, 4);
        ata_entry(&mut d, 5, 199, 200, 200, 0);
        ata_entry(&mut d, 6, 1, 5, 5, 0);
        let mut t = vec![0u8; 512];
        for (slot, (id, th)) in [(5u8, 36u8), (9, 0), (12, 0), (194, 0), (197, 0), (199, 0), (1, 6)].iter().enumerate() {
            t[2 + slot * 12] = *id;
            t[2 + slot * 12 + 1] = *th;
        }
        let attrs = parse_ata_attributes(&d, Some(&t));
        assert_eq!(attrs.len(), 7);
        let a = |id| attrs.iter().find(|a| a.id == id).unwrap();
        assert_eq!((a(5).raw, a(5).status.as_str(), a(5).threshold), (8, "warn", 36));
        assert_eq!(a(9).raw, 8000);
        assert_eq!(a(194).raw, 36);
        assert_eq!(a(199).status, "ok");
        assert_eq!((a(1).status.as_str(), a(1).name.as_str()), ("fail", "Read error rate"));

        let mut info = SmartInfo { health: "Unknown".into(), ..Default::default() };
        apply_ata(&mut info, attrs);
        finish(&mut info);
        assert_eq!(info.source, "ATA SMART");
        assert_eq!((info.temperature_c, info.power_on_hours, info.power_cycles), (Some(36), Some(8000), Some(321)));
        assert_eq!((info.reallocated_sectors, info.pending_sectors), (Some(8), Some(4)));
        assert_eq!(info.health, "Unhealthy");
        assert_eq!(info.warnings[0], format!("12 sectors are failing. {IMAGE_FIRST}"));
        assert!(info.warnings.iter().any(|w| w.contains("read error rate")));
    }

    /// Unelevated on this machine: whatever Windows lets us read, without errors.
    #[test]
    fn real_disk_0() {
        let i = read(0).expect("disk 0");
        println!("{}", serde_json::to_string_pretty(&i).unwrap());
        assert!(matches!(i.health.as_str(), "Healthy" | "Warning" | "Unhealthy" | "Unknown"));
        assert!(i.available || i.needs_admin);
    }
}
