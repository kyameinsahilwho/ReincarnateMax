//! Structure parsers: from a header hit, work out where the file ends.

use super::rd::Rd;
use super::sig::Fam;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum End {
    /// The walk ended at a proper end marker / declared size.
    Clean,
    /// The end was estimated (no end marker in the format, or it wasn't found).
    Estimated,
    /// Invalid data or unreadable sectors before the end.
    Damaged,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Parsed {
    /// Specific type when the parser decided it (else `formats::detect` / the family default).
    pub ty: Option<&'static str>,
    pub len: u64,
    pub end: End,
    /// Two or more (relative offset, length) pieces when the file was rebuilt from fragments.
    pub frags: Vec<(u64, u64)>,
    /// The length isn't backed by the structure (clipped at the end of the source): a later
    /// header cuts it, like an estimated end.
    pub soft: bool,
}

pub(crate) fn clean(len: u64) -> Option<Parsed> {
    (len > 0).then_some(Parsed { ty: None, len, end: End::Clean, frags: Vec::new(), soft: false })
}
pub(crate) fn est(len: u64) -> Option<Parsed> {
    (len > 0).then_some(Parsed { ty: None, len, end: End::Estimated, frags: Vec::new(), soft: false })
}
pub(crate) fn dmg(len: u64) -> Option<Parsed> {
    (len > 0).then_some(Parsed { ty: None, len, end: End::Damaged, frags: Vec::new(), soft: false })
}
/// Damaged because it runs past the end of the source: kept up to there, cut by later headers.
pub(crate) fn clip(len: u64) -> Option<Parsed> {
    (len > 0).then_some(Parsed { ty: None, len, end: End::Damaged, frags: Vec::new(), soft: true })
}
pub(crate) fn typed(p: Option<Parsed>, ty: &'static str) -> Option<Parsed> {
    p.map(|mut p| {
        p.ty = Some(ty);
        p
    })
}

/// `Ok(v)` or return Damaged at `pos`.
macro_rules! or_dmg {
    ($e:expr, $pos:expr) => {
        match $e {
            Ok(v) => v,
            Err(_) => return crate::carve::parse::dmg($pos),
        }
    };
}
pub(crate) use or_dmg;

/// What the parsers know about the rest of the scan.
pub(crate) struct Env<'a> {
    /// Cluster size (bytes) for fragment searches.
    pub cluster: u64,
    /// Sorted absolute offsets of every header hit.
    pub hits: &'a [u64],
}

impl Env<'_> {
    /// The first hit after `abs`.
    pub fn next_hit(&self, abs: u64) -> Option<u64> {
        let i = self.hits.partition_point(|&h| h <= abs);
        self.hits.get(i).copied()
    }
}

/// A file whose size is declared in its header: Clean when it fits on the source and its last
/// byte is readable, Damaged (clipped) otherwise. `None` when the size is absurd.
pub(crate) fn sized(rd: &mut Rd, len: u64, min: u64, cap: u64) -> Option<Parsed> {
    if len < min || len > cap {
        return None;
    }
    let avail = rd.avail();
    if len > avail {
        return clip(avail);
    }
    if rd.bytes(len - 1, 1).is_err() {
        return dmg(len);
    }
    clean(len)
}

pub(crate) fn run(fam: Fam, rd: &mut Rd, env: &Env) -> Option<Parsed> {
    let avail = rd.avail();
    let mut p = run_inner(fam, rd, env)?;
    if p.frags.is_empty() && p.len > avail {
        // Ran past the end of the source: keep what's there, let later headers cut it.
        p.len = avail;
        p.end = End::Damaged;
        p.soft = true;
    }
    (p.len > 0).then_some(p)
}

fn run_inner(fam: Fam, rd: &mut Rd, env: &Env) -> Option<Parsed> {
    use super::{arc, av, doc, img, jpeg};
    use Fam::*;
    match fam {
        Jpeg => jpeg::parse(rd, env),
        Png => img::png(rd),
        Gif => img::gif(rd),
        Bmp => img::bmp(rd),
        Tiff => img::tiff(rd, env),
        Raf => img::raf(rd),
        X3f => img::x3f(rd, env),
        Psd => img::psd(rd),
        Ico => img::ico(rd),
        Riff => av::riff(rd, env),
        Aiff => av::aiff(rd),
        Bmff => av::bmff(rd, env),
        Ebml => av::ebml(rd),
        Asf => av::asf(rd),
        Flv => av::flv(rd),
        MpegPs => av::mpeg_ps(rd),
        MpegTs => av::ts(rd, 0, 188),
        Mts => av::ts(rd, 4, 192),
        Mp3 => av::mp3(rd),
        Flac => av::flac(rd),
        Ogg => av::ogg(rd),
        Aac => av::aac(rd),
        Amr => av::amr(rd),
        Midi => av::midi(rd),
        Pdf => doc::pdf(rd, env),
        Rtf => doc::rtf(rd),
        Eml => doc::eml(rd),
        Pst => doc::pst(rd),
        Ole => doc::ole(rd),
        Sqlite => doc::sqlite(rd, env),
        Pe => doc::pe(rd),
        Zip => super::zip::parse(rd, env),
        SevenZ => arc::sevenz(rd),
        Rar => arc::rar(rd),
        Gzip => arc::gzip(rd),
        Bz2 => arc::bz2(rd, env),
        Xz => arc::xz(rd),
        Tar => arc::tar(rd),
        Cab => arc::cab(rd),
        Iso => arc::iso(rd),
    }
}
