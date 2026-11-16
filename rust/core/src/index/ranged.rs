//! Reading a wheel without downloading all of it.
//!
//! A wheel is a zip, and a zip's index (the central directory) sits at the end of the file, so an
//! HTTP `Range` request for the tail finds every entry, and further small ranges fetch just the
//! entries wanted: `METADATA` and the license files. That is kilobytes where the whole wheel is
//! megabytes. A server that ignores `Range` gets the plain full download instead.

use super::{Client, IndexError};
use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

/// How much to ask for at a time. The central directory and entries are read nearly sequentially,
/// so fetching ahead saves round trips.
const BLOCK: u64 = 128 * 1024;
const READ_AHEAD_BLOCKS: u64 = 2;

/// A byte range of a remote file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteRange {
    /// The last `n` bytes.
    Suffix(u64),
    /// Bytes `start` to `end` inclusive.
    Span { start: u64, end: u64 },
}

impl ByteRange {
    /// The value of the `Range` header.
    #[must_use]
    pub fn header(self) -> String {
        match self {
            Self::Suffix(count) => format!("bytes=-{count}"),
            Self::Span { start, end } => format!("bytes={start}-{end}"),
        }
    }
}

/// Part of a remote file, and how long the whole file is.
#[derive(Clone, Debug)]
pub struct RangeResponse {
    pub start: u64,
    pub total: u64,
    pub body: Vec<u8>,
}

/// Parse `Content-Range: bytes START-END/TOTAL`.
#[must_use]
pub fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let rest = value.trim().strip_prefix("bytes")?.trim_start();
    let (span, total) = rest.split_once('/')?;
    let (start, end) = span.split_once('-')?;
    Some((
        start.trim().parse().ok()?,
        end.trim().parse().ok()?,
        total.trim().parse().ok()?,
    ))
}

/// A remote file that reads (and seeks) by fetching the ranges it needs.
pub struct RangedReader<'a> {
    client: &'a dyn Client,
    url: String,
    len: u64,
    position: u64,
    segments: BTreeMap<u64, Vec<u8>>,
}

impl<'a> RangedReader<'a> {
    /// Open `url` by fetching its tail. `Ok(None)` when the server does not do ranges.
    ///
    /// # Errors
    ///
    /// When the request fails.
    pub fn open(client: &'a dyn Client, url: &str) -> Result<Option<Self>, IndexError> {
        let Some(tail) = client.get_range(url, ByteRange::Suffix(BLOCK))? else {
            return Ok(None);
        };
        let mut segments = BTreeMap::new();
        segments.insert(tail.start, tail.body);
        Ok(Some(Self {
            client,
            url: url.to_owned(),
            len: tail.total,
            position: 0,
            segments,
        }))
    }

    fn segment_at(&self, position: u64) -> Option<(&u64, &Vec<u8>)> {
        self.segments
            .range(..=position)
            .next_back()
            .filter(|(start, body)| **start + body.len() as u64 > position)
    }

    fn fill(&mut self, position: u64) -> io::Result<()> {
        if self.segment_at(position).is_some() {
            return Ok(());
        }
        let start = position / BLOCK * BLOCK;
        let end = (start + READ_AHEAD_BLOCKS * BLOCK).min(self.len) - 1;
        let response = self
            .client
            .get_range(&self.url, ByteRange::Span { start, end })
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::other("the server stopped honouring range requests"))?;
        if response.start > position || response.start + response.body.len() as u64 <= position {
            return Err(io::Error::other(
                "the server returned a different range than asked for",
            ));
        }
        self.segments.insert(response.start, response.body);
        Ok(())
    }
}

impl Read for RangedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.len {
            return Ok(0);
        }
        self.fill(self.position)?;
        let position = self.position;
        let (start, body) = self
            .segment_at(position)
            .ok_or_else(|| io::Error::other("range cache lost a segment"))?;
        let offset = usize::try_from(position - start).map_err(io::Error::other)?;
        let count = buf.len().min(body.len() - offset);
        buf[..count].copy_from_slice(&body[offset..offset + count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for RangedReader<'_> {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the file",
            )
        };
        let next = match target {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(offset) => self.len.checked_add_signed(offset),
            SeekFrom::Current(offset) => self.position.checked_add_signed(offset),
        };
        self.position = next.ok_or_else(invalid)?;
        Ok(self.position)
    }
}

/// A wheel, read by ranges where the server allows and from memory otherwise.
pub enum WheelSource<'a> {
    Ranged(RangedReader<'a>),
    Memory(Cursor<Vec<u8>>),
}

impl Read for WheelSource<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Ranged(reader) => reader.read(buf),
            Self::Memory(cursor) => cursor.read(buf),
        }
    }
}

impl Seek for WheelSource<'_> {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        match self {
            Self::Ranged(reader) => reader.seek(target),
            Self::Memory(cursor) => cursor.seek(target),
        }
    }
}

/// Open the wheel at `url`: by ranges if the server supports them and the file is big enough to be
/// worth it, else downloaded whole (up to `max_bytes`). `size_hint` is the file's size when known.
///
/// # Errors
///
/// When the wheel cannot be fetched, or is too large to download whole.
pub fn open_wheel<'a>(
    client: &'a dyn Client,
    url: &str,
    size_hint: Option<u64>,
    max_bytes: usize,
) -> Result<WheelSource<'a>, IndexError> {
    // A file no bigger than one fetch is cheaper whole than by ranges, and some servers refuse a
    // suffix range longer than the file (416) instead of returning all of it.
    let small = size_hint.is_some_and(|size| size <= BLOCK);
    if !small {
        if let Some(reader) = RangedReader::open(client, url)? {
            return Ok(WheelSource::Ranged(reader));
        }
    }
    let response = client.get(url, None, Some(max_bytes))?;
    Ok(WheelSource::Memory(Cursor::new(response.body)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serves one file by ranges, counting requests.
    struct Remote {
        data: Vec<u8>,
        ranges: bool,
        log: Mutex<Vec<ByteRange>>,
    }

    impl Client for Remote {
        fn get(
            &self,
            _url: &str,
            _accept: Option<&str>,
            max: Option<usize>,
        ) -> Result<super::super::Response, IndexError> {
            if max.is_some_and(|max| self.data.len() > max) {
                return Err(IndexError::Query("too large".to_owned()));
            }
            Ok(super::super::Response {
                url: String::new(),
                content_type: String::new(),
                body: self.data.clone(),
            })
        }

        fn credentials_for(&self, _url: &str) -> String {
            "none".to_owned()
        }

        fn get_range(
            &self,
            _url: &str,
            range: ByteRange,
        ) -> Result<Option<RangeResponse>, IndexError> {
            if !self.ranges {
                return Ok(None);
            }
            self.log.lock().expect("lock").push(range);
            let total = self.data.len() as u64;
            let (start, end) = match range {
                ByteRange::Suffix(count) => (total.saturating_sub(count), total - 1),
                ByteRange::Span { start, end } => (start, end.min(total - 1)),
            };
            Ok(Some(RangeResponse {
                start,
                total,
                body: self.data
                    [usize::try_from(start).expect("start")..=usize::try_from(end).expect("end")]
                    .to_vec(),
            }))
        }
    }

    fn remote(size: usize, ranges: bool) -> Remote {
        Remote {
            data: (0..size)
                .map(|i| u8::try_from(i % 251).expect("byte"))
                .collect(),
            ranges,
            log: Mutex::new(Vec::new()),
        }
    }

    #[test]
    fn content_range_headers_parse() {
        assert_eq!(
            parse_content_range("bytes 100-199/5000"),
            Some((100, 199, 5000))
        );
        assert_eq!(parse_content_range("bytes 0-0/1"), Some((0, 0, 1)));
        assert_eq!(parse_content_range("bytes */5000"), None);
        assert_eq!(parse_content_range("items 1-2/3"), None);
        assert_eq!(ByteRange::Suffix(10).header(), "bytes=-10");
        assert_eq!(ByteRange::Span { start: 5, end: 9 }.header(), "bytes=5-9");
    }

    #[test]
    fn reads_match_the_file_wherever_they_land_and_fetch_only_what_is_needed() {
        let remote = remote(1_000_000, true);
        let mut reader = RangedReader::open(&remote, "u")
            .expect("open")
            .expect("ranges");
        let mut buf = [0u8; 100];
        for position in [999_900_u64, 0, 500_000, 131_000, 131_072, 999_999 - 99] {
            reader.seek(SeekFrom::Start(position)).expect("seek");
            reader.read_exact(&mut buf).expect("read");
            let at = usize::try_from(position).expect("position");
            assert_eq!(&buf[..], &remote.data[at..at + 100], "at {position}");
        }
        // The tail, then one read-ahead span per distinct region touched: three requests, not one
        // per read.
        assert_eq!(remote.log.lock().expect("lock").len(), 3);
    }

    #[test]
    fn a_read_spanning_two_fetched_segments_is_stitched_together() {
        let remote = remote(600_000, true);
        let mut reader = RangedReader::open(&remote, "u")
            .expect("open")
            .expect("ranges");
        reader.seek(SeekFrom::Start(BLOCK * 2 - 50)).expect("seek");
        let mut buf = vec![0u8; 300_000];
        reader.read_exact(&mut buf).expect("read");
        let at = usize::try_from(BLOCK * 2 - 50).expect("at");
        assert_eq!(buf, remote.data[at..at + 300_000]);
    }

    #[test]
    fn seeking_from_the_end_and_past_it_behaves_like_a_file() {
        let remote = remote(10_000, true);
        let mut reader = RangedReader::open(&remote, "u")
            .expect("open")
            .expect("ranges");
        assert_eq!(reader.seek(SeekFrom::End(-4)).expect("seek"), 9_996);
        let mut buf = [0u8; 10];
        assert_eq!(
            reader.read(&mut buf).expect("read"),
            4,
            "only the last four bytes remain"
        );
        assert_eq!(reader.read(&mut buf).expect("read"), 0, "end of file");
        assert!(reader.seek(SeekFrom::Current(-20_000)).is_err());
    }

    #[test]
    fn a_server_without_ranges_falls_back_to_a_capped_full_download() {
        let remote = remote(5_000, false);
        assert!(RangedReader::open(&remote, "u").expect("open").is_none());
        assert!(matches!(
            open_wheel(&remote, "u", None, 10_000).expect("whole"),
            WheelSource::Memory(_)
        ));
        assert!(
            open_wheel(&remote, "u", None, 100).is_err(),
            "the cap still applies to a full download"
        );
    }

    #[test]
    fn a_small_file_is_read_in_one_request() {
        let remote = remote(500, true);
        let mut reader = RangedReader::open(&remote, "u")
            .expect("open")
            .expect("ranges");
        let mut all = Vec::new();
        reader.read_to_end(&mut all).expect("read");
        assert_eq!(all, remote.data);
        assert_eq!(remote.log.lock().expect("lock").len(), 1);
    }
}
