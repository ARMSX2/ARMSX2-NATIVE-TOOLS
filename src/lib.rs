/*
    armsx2-native-tools - Native tools for the ARMSX2 project this library will include helpers and tools for use in the Android, iOS and Xbox/PC A(RM)SX2 apps.
    see LICENSE for license information.
*/

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use sha1::{Digest, Sha1};
use std::ffi::CStr;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};
use thiserror::Error;

const CHD_HEADER_TAG: &[u8; 8] = b"MComprHD";
const CHD_HEADER_SIZE: usize = 124;
const CHD_VERSION_V5: u32 = 5;
const DEFAULT_HUNK_BYTES: u32 = 0x80000; // 512 KiB, maximum allowed for V5
const DEFAULT_UNIT_BYTES: u32 = 2048; // ISO sector size
const SHA1_LEN: usize = 20;

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversionStatus {
    Success = 0,
    NullPointer = -1,
    InvalidUtf8 = -2,
    InputNotFound = -3,
    InputNotFile = -4,
    OutputCreateFailed = -5,
    IoError = -6,
    TooManyHunks = -7,
    Overflow = -8,
    UnexpectedEof = -9,
    Internal = -100,
}

#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("input ISO not found: {0}")]
    InputNotFound(PathBuf),
    #[error("input path is not a regular file: {0}")]
    InputNotFile(PathBuf),
    #[error("failed to create output file {0}: {1}")]
    OutputCreate(PathBuf, #[source] io::Error),
    #[error("I/O error")]
    Io(#[from] io::Error),
    #[error("too many hunks for CHD map: {0}")]
    TooManyHunks(u64),
    #[error("map size overflow")]
    MapOverflow,
    #[error("alignment overflow")]
    AlignmentOverflow,
    #[error("unexpected end of ISO data")]
    UnexpectedEof,
}

impl ConversionStatus {
    fn from_error(err: &ConversionError) -> Self {
        match err {
            ConversionError::InputNotFound(_) => ConversionStatus::InputNotFound,
            ConversionError::InputNotFile(_) => ConversionStatus::InputNotFile,
            ConversionError::OutputCreate(_, _) => ConversionStatus::OutputCreateFailed,
            ConversionError::Io(_) => ConversionStatus::IoError,
            ConversionError::TooManyHunks(_) => ConversionStatus::TooManyHunks,
            ConversionError::MapOverflow | ConversionError::AlignmentOverflow => {
                ConversionStatus::Overflow
            }
            ConversionError::UnexpectedEof => ConversionStatus::UnexpectedEof,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_iso_to_chd(
    input_iso_path: *const c_char,
    output_chd_path: *const c_char,
) -> c_int {
    if input_iso_path.is_null() || output_chd_path.is_null() {
        return ConversionStatus::NullPointer as c_int;
    }

    let input = match unsafe { CStr::from_ptr(input_iso_path) }.to_str() {
        Ok(path) => PathBuf::from(path),
        Err(_) => return ConversionStatus::InvalidUtf8 as c_int,
    };

    let output = match unsafe { CStr::from_ptr(output_chd_path) }.to_str() {
        Ok(path) => PathBuf::from(path),
        Err(_) => return ConversionStatus::InvalidUtf8 as c_int,
    };

    match convert_iso_to_chd_internal(&input, &output) {
        Ok(()) => ConversionStatus::Success as c_int,
        Err(err) => ConversionStatus::from_error(&err) as c_int,
    }
}

fn convert_iso_to_chd_internal(input: &Path, output: &Path) -> Result<(), ConversionError> {
    let metadata = fs::metadata(input).map_err(|err| match err.kind() {
        io::ErrorKind::NotFound => ConversionError::InputNotFound(input.to_path_buf()),
        _ => ConversionError::Io(err),
    })?;

    if !metadata.is_file() {
        return Err(ConversionError::InputNotFile(input.to_path_buf()));
    }

    let iso_size = metadata.len();

    let hunk_bytes = DEFAULT_HUNK_BYTES as u64;
    let hunk_count = if iso_size == 0 {
        0
    } else {
        (iso_size + hunk_bytes - 1) / hunk_bytes
    };

    if hunk_count > u32::MAX as u64 {
        return Err(ConversionError::TooManyHunks(hunk_count));
    }

    let map_size = hunk_count
        .checked_mul(4)
        .ok_or(ConversionError::MapOverflow)?;
    let map_offset = CHD_HEADER_SIZE as u64;
    let map_end = map_offset
        .checked_add(map_size)
        .ok_or(ConversionError::MapOverflow)?;

    let data_offset = if hunk_count == 0 {
        map_end
    } else {
        align_up(map_end, hunk_bytes).ok_or(ConversionError::AlignmentOverflow)?
    };

    let base_hunk_index = if hunk_count == 0 {
        0
    } else {
        (data_offset / hunk_bytes) as u32
    };

    let mut iso_file = File::open(input).map_err(|err| match err.kind() {
        io::ErrorKind::NotFound => ConversionError::InputNotFound(input.to_path_buf()),
        _ => ConversionError::Io(err),
    })?;

    let mut chd_file = File::create(output)
        .map_err(|err| ConversionError::OutputCreate(output.to_path_buf(), err))?;

    write_header_placeholder(&mut chd_file)?;
    write_map_entries(&mut chd_file, hunk_count as usize, base_hunk_index)?;
    write_padding(&mut chd_file, data_offset - map_end)?;

    if hunk_count > 0 {
        chd_file.seek(SeekFrom::Start(data_offset))?;
    }

    let digest = write_payload(&mut iso_file, &mut chd_file, iso_size, hunk_count)?;
    finalize_header(&mut chd_file, iso_size, map_offset, digest)?;

    Ok(())
}

fn write_header_placeholder(file: &mut File) -> io::Result<()> {
    file.write_all(&[0u8; CHD_HEADER_SIZE])
}

fn write_map_entries(
    file: &mut File,
    hunk_count: usize,
    base_hunk_index: u32,
) -> Result<(), ConversionError> {
    let mut entry_buf = [0u8; 4];
    for idx in 0..hunk_count {
        let entry_value = base_hunk_index
            .checked_add(idx as u32)
            .ok_or(ConversionError::MapOverflow)?;
        BigEndian::write_u32(&mut entry_buf, entry_value);
        file.write_all(&entry_buf)?;
    }
    Ok(())
}

fn write_padding(file: &mut File, padding_len: u64) -> io::Result<()> {
    if padding_len == 0 {
        return Ok(());
    }

    const ZERO_CHUNK: [u8; 4096] = [0u8; 4096];
    let mut remaining = padding_len;
    while remaining > 0 {
        let to_write = std::cmp::min(remaining, ZERO_CHUNK.len() as u64) as usize;
        file.write_all(&ZERO_CHUNK[..to_write])?;
        remaining -= to_write as u64;
    }
    Ok(())
}

fn write_payload(
    iso: &mut File,
    chd: &mut File,
    iso_size: u64,
    hunk_count: u64,
) -> Result<[u8; SHA1_LEN], ConversionError> {
    let mut hasher = Sha1::new();
    let mut buffer = vec![0u8; DEFAULT_HUNK_BYTES as usize];
    let mut bytes_remaining = iso_size;

    for _ in 0..hunk_count {
        let chunk_size = std::cmp::min(buffer.len() as u64, bytes_remaining) as usize;
        if chunk_size > 0 {
            iso.read_exact(&mut buffer[..chunk_size]).map_err(|err| {
                if err.kind() == io::ErrorKind::UnexpectedEof {
                    ConversionError::UnexpectedEof
                } else {
                    ConversionError::Io(err)
                }
            })?;
            hasher.update(&buffer[..chunk_size]);
        } else {
            buffer.fill(0);
        }

        if chunk_size < buffer.len() {
            buffer[chunk_size..].fill(0);
        }

        chd.write_all(&buffer)?;
        bytes_remaining = bytes_remaining.saturating_sub(chunk_size as u64);
    }

    if bytes_remaining != 0 {
        return Err(ConversionError::UnexpectedEof);
    }

    let digest = hasher.finalize();
    let mut sha = [0u8; SHA1_LEN];
    sha.copy_from_slice(&digest);
    Ok(sha)
}

fn finalize_header(
    file: &mut File,
    logical_bytes: u64,
    map_offset: u64,
    sha1: [u8; SHA1_LEN],
) -> io::Result<()> {
    let mut header = [0u8; CHD_HEADER_SIZE];
    header[..8].copy_from_slice(CHD_HEADER_TAG);
    {
        let mut cursor = io::Cursor::new(&mut header[8..]);
        cursor.write_u32::<BigEndian>(CHD_HEADER_SIZE as u32)?;
        cursor.write_u32::<BigEndian>(CHD_VERSION_V5)?;
        // compressors[0..4]
        cursor.write_u32::<BigEndian>(0)?; // CHD_CODEC_NONE
        cursor.write_u32::<BigEndian>(0)?;
        cursor.write_u32::<BigEndian>(0)?;
        cursor.write_u32::<BigEndian>(0)?;
        cursor.write_u64::<BigEndian>(logical_bytes)?;
        cursor.write_u64::<BigEndian>(map_offset)?;
        cursor.write_u64::<BigEndian>(0)?; // meta offset
        cursor.write_u32::<BigEndian>(DEFAULT_HUNK_BYTES)?;
        cursor.write_u32::<BigEndian>(DEFAULT_UNIT_BYTES)?;
        cursor.write_all(&sha1)?; // raw SHA1
        cursor.write_all(&sha1)?; // combined SHA1 (no metadata)
        cursor.write_all(&[0u8; SHA1_LEN])?; // parent SHA1
    }

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header)?;
    Ok(())
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 {
        return Some(value);
    }
    let rem = value % alignment;
    if rem == 0 {
        Some(value)
    } else {
        value.checked_add(alignment - rem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chd::read::ChdReader;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn iso_to_chd_roundtrip() {
        let mut iso_file = NamedTempFile::new().expect("create iso temp file");
        let chd_file = NamedTempFile::new().expect("create chd temp file");

        let mut data = Vec::new();
        for i in 0..(DEFAULT_HUNK_BYTES as usize + 1024) {
            data.push((i % 251) as u8);
        }
        iso_file.write_all(&data).expect("write iso data");
        iso_file.flush().expect("flush iso data");

        convert_iso_to_chd_internal(iso_file.path(), chd_file.path()).expect("convert iso");

        let file = File::open(chd_file.path()).expect("open chd file");
        let chd = chd::Chd::open(file, None).expect("open chd");
        assert_eq!(chd.header().logical_bytes(), data.len() as u64);
        assert_eq!(chd.header().hunk_size(), DEFAULT_HUNK_BYTES);
        assert_eq!(chd.header().unit_bytes(), DEFAULT_UNIT_BYTES);

        let mut reader = ChdReader::new(chd);
        let mut restored = vec![0u8; data.len()];
        reader.read_exact(&mut restored).expect("read back data");
        assert_eq!(restored, data);
    }
}
