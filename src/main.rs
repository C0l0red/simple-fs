extern crate core;

use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::{Deref, DerefMut};
use std::path::Path;

fn main() {
    println!("Hello, world!");
}

const MAGIC_NUMBER: u32 = 0x4D594653; // "MYFS" in ASCII
const INODE_COUNT: u32 = 8;
const INODE_SIZE: u32 = 9;
const BLOCK_SIZE: u32 = 4096;
const TOTAL_BLOCKS: u32 = 16;
const FILE_NAME_SIZE: usize = 250;
const DIRECTORY_ENTRY_SIZE: usize = 256;
const INODE_BITMAP_BLOCK: u32 = 1;
const BLOCK_BITMAP_BLOCK: u32 = 2;
const INODE_TABLE_BLOCK: u32 = 3;
const DATA_BLOCK_START: u32 = 4;

#[derive(Debug, PartialEq)]
enum Error {
    Validation(String),
    IO(String),
    EntryNotFound { entry: String, directory: String },
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err.to_string())
    }
}

trait BlockDevice {
    fn read_block(&mut self, block_index: u32, buffer: &mut BlockBuffer) -> Result<(), Error>;
    fn write_block(&mut self, block_index: u32, data: &mut BlockBuffer) -> Result<(), Error>;
    fn block_size(&self) -> u32;
    fn total_blocks(&self) -> u32;
}

struct BlockBuffer([u8; BLOCK_SIZE as usize]);

struct ImgFileDisk {
    file: File,
    block_size: u32,
    total_blocks: u32,
}

struct MyFS<D: BlockDevice> {
    device: D,
    superblock: Superblock,
    inode_bitmap: Bitmap,
    block_bitmap: Bitmap,
    inodes: Vec<Inode>,
}

struct Superblock {
    magic_number: u32,
    version: u32,
    block_size: u32,
    total_blocks: u32,
    inode_count: u32,
    inode_size: u32,
    inode_bitmap_start: u32,
    block_bitmap_start: u32,
    inode_table_start: u32,
    data_block_start: u32,
}

struct Bitmap(Vec<u8>);

#[derive(Copy, Clone)]
struct Inode {
    file_type: FileType,
    size: u32,
    direct_block: u32,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
enum FileType {
    File = 0u8,
    Directory = 1u8,
}

struct Filename([u8; FILE_NAME_SIZE]);

struct DirectoryEntry {
    inode_number: u32,
    file_type: FileType,
    name_length: u8,
    name: Filename,
}

struct Directory(Vec<DirectoryEntry>);

impl BlockBuffer {
    fn new() -> Self {
        Self([0u8; BLOCK_SIZE as usize])
    }

    fn is_empty(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl Deref for BlockBuffer {
    type Target = [u8; BLOCK_SIZE as usize];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BlockBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for Bitmap {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Bitmap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Bitmap {
    fn new(bytes: &BlockBuffer) -> Self {
        Self(bytes.to_vec())
    }

    fn create_and_occupy_first_n_bits(occupied_offset: usize) -> Self {
        let mut bitmap = Self::new(&BlockBuffer::new());
        let full_bytes = occupied_offset / 8;
        let remaining_bits = occupied_offset % 8;

        // set complete bytes
        for i in 0..full_bytes {
            bitmap[i] = 0xFF;
        }

        // set remaining bits in the next byte
        if remaining_bits > 0 {
            bitmap[full_bytes] |= (1 << remaining_bits) - 1;
        }
        bitmap
    }

    fn set_bit(&mut self, index: usize) {
        let byte = index / 8;
        let bit = index % 8;
        self[byte] |= 1 << bit;
    }

    fn clear_bit(&mut self, index: usize) {
        let byte = index / 8;
        let bit = index % 8;
        self[byte] &= !(1 << bit);
    }

    fn is_bit_set(&self, index: usize) -> bool {
        let byte = index / 8;
        let bit = index % 8;
        self[byte] & (1 << bit) != 0
    }
}

impl TryFrom<u8> for FileType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::File),
            1 => Ok(Self::Directory),
            _ => Err(Error::Validation("Invalid inode kind".to_string())),
        }
    }
}

impl Inode {
    fn new(file_type: FileType, size: u32, direct_block: u32) -> Self {
        Self {
            file_type,
            size,
            direct_block,
        }
    }
}

impl Deref for Directory {
    type Target = Vec<DirectoryEntry>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Filename {
    fn new(name: String) -> Self {
        let mut bytes = [0u8; FILE_NAME_SIZE];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Self(bytes)
    }

    fn len(&self) -> usize {
        self.iter().position(|&b| b == 0).unwrap_or(self.0.len())
    }
}

impl Deref for Filename {
    type Target = [u8; FILE_NAME_SIZE];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Filename {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for Filename {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let copy = self.to_vec();
        let end = copy.iter().position(|&b| b == 0).unwrap_or(copy.len());
        write!(f, "{}", String::from_utf8_lossy(&copy[..end]))
    }
}

trait BytesSerializable {
    fn bytes_to_u32(bytes: &[u8]) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
            Error::Validation("Bytes to u32 conversion failed".to_string())
        })?))
    }

    fn to_bytes(&self) -> Vec<u8>;
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
}

impl BytesSerializable for Inode {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0u8; INODE_SIZE as usize];

        bytes[0] = self.file_type as u8;
        bytes[1..5].copy_from_slice(&self.size.to_le_bytes());
        bytes[5..9].copy_from_slice(&self.direct_block.to_le_bytes());

        bytes
    }

    fn try_from_bytes(buffer: &[u8]) -> Result<Self, Error> {
        if buffer.len() < INODE_SIZE as usize {
            return Err(Error::Validation(
                "Buffer is too short to contain an Inode".to_string(),
            ));
        }

        Ok(Inode {
            file_type: FileType::try_from(buffer[0])?,
            size: Self::bytes_to_u32(&buffer[1..5])?,
            direct_block: Self::bytes_to_u32(&buffer[5..9])?,
        })
    }
}

impl BytesSerializable for Superblock {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0u8; BLOCK_SIZE as usize];

        bytes[0..4].copy_from_slice(&self.magic_number.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.version.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.block_size.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.total_blocks.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.inode_count.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.inode_size.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.inode_bitmap_start.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.block_bitmap_start.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.inode_table_start.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.data_block_start.to_le_bytes());

        bytes
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < BLOCK_SIZE as usize {
            return Err(Error::Validation(
                "Buffer is too short to contain a Superblock".to_string(),
            ));
        }

        Ok(Superblock {
            magic_number: Self::bytes_to_u32(&bytes[0..4])?,
            version: Self::bytes_to_u32(&bytes[4..8])?,
            block_size: Self::bytes_to_u32(&bytes[8..12])?,
            total_blocks: Self::bytes_to_u32(&bytes[12..16])?,
            inode_count: Self::bytes_to_u32(&bytes[16..20])?,
            inode_size: Self::bytes_to_u32(&bytes[20..24])?,
            inode_bitmap_start: Self::bytes_to_u32(&bytes[24..28])?,
            block_bitmap_start: Self::bytes_to_u32(&bytes[28..32])?,
            inode_table_start: Self::bytes_to_u32(&bytes[32..36])?,
            data_block_start: Self::bytes_to_u32(&bytes[36..40])?,
        })
    }
}

impl BytesSerializable for DirectoryEntry {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0u8; DIRECTORY_ENTRY_SIZE];

        bytes[0..4].copy_from_slice(&self.inode_number.to_le_bytes());
        bytes[4] = self.file_type as u8;
        bytes[5] = self.name_length;
        bytes[6..DIRECTORY_ENTRY_SIZE].copy_from_slice(&self.name.0);

        bytes
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if bytes.len() < DIRECTORY_ENTRY_SIZE {
            return Err(Error::Validation(
                "Byte array is too short to contain a DirectoryEntry".to_string(),
            ));
        }

        let name: [u8; FILE_NAME_SIZE] = bytes[6..DIRECTORY_ENTRY_SIZE]
            .try_into()
            .map_err(|_| Error::Validation("Invalid name length".into()))?;
        let name = Filename(name);

        Ok(Self {
            inode_number: Self::bytes_to_u32(&bytes[0..4])?,
            file_type: FileType::try_from(bytes[4])?,
            name_length: bytes[5],
            name,
        })
    }
}

// This is a repetition of serializing and deserializing directory entry in a vector,
// But it is necessary for speed to avoid creating bytes on the heap repeatedly when transforming a
// directory to bytes
impl BytesSerializable for Directory {
    fn to_bytes(&self) -> Vec<u8> {
        // Assert elsewhere that directory is not too big for the block
        let mut buffer = vec![0u8; DIRECTORY_ENTRY_SIZE * self.len()];
        for (i, entry) in self.iter().enumerate() {
            let start_index = i * DIRECTORY_ENTRY_SIZE;
            buffer[start_index..start_index + 4].copy_from_slice(&entry.inode_number.to_le_bytes());
            buffer[start_index + 4] = entry.file_type as u8;
            buffer[start_index + 5] = entry.name_length;
            buffer[start_index + 6..start_index + 6 + FILE_NAME_SIZE]
                .copy_from_slice(&entry.name.0);
        }

        buffer
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if bytes.len() % DIRECTORY_ENTRY_SIZE != 0 {
            return Err(Error::Validation(
                "Byte array is not a multiple of DIRECTORY_ENTRY_SIZE".to_string(),
            ));
        }

        let mut cursor = 0;
        let mut entries = Vec::with_capacity(bytes.len() / DIRECTORY_ENTRY_SIZE);

        while cursor < bytes.len() {
            let entry_bytes = &bytes[cursor..cursor + DIRECTORY_ENTRY_SIZE];
            let entry = DirectoryEntry::try_from_bytes(entry_bytes)?;

            cursor += DIRECTORY_ENTRY_SIZE;
            entries.push(entry);
        }

        Ok(Directory(entries))
    }
}

impl ImgFileDisk {
    fn open(path: &Path) -> Result<Self, Error> {
        if !path.is_file() {
            return Err(Error::IO("Disk file not found".to_string()));
        }
        if !path
            .extension()
            .is_some_and(|ext| ext.to_str() == Some("img"))
        {
            return Err(Error::Validation(
                "Disk file is not an img file".to_string(),
            ));
        }

        Ok(ImgFileDisk {
            file: File::options()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|_| Error::IO("Could not open disk file".to_string()))?,
            block_size: BLOCK_SIZE,
            total_blocks: TOTAL_BLOCKS,
        })
    }
}

impl BlockDevice for ImgFileDisk {
    fn read_block(&mut self, block_index: u32, buffer: &mut BlockBuffer) -> Result<(), Error> {
        if buffer.len() < self.block_size as usize {
            return Err(Error::Validation(
                "Buffer is too small to contain a block".to_string(),
            ));
        }
        self.file
            .seek(SeekFrom::Start((block_index * self.block_size) as u64))
            .map_err(|_| {
                Error::IO("Could not seek while reading block from img file".to_string())
            })?;
        self.file
            .read_exact(buffer.deref_mut())
            .map_err(|_| Error::IO("Could not read block from img file".to_string()))?;

        Ok(())
    }

    fn write_block(&mut self, block_index: u32, buffer: &mut BlockBuffer) -> Result<(), Error> {
        if buffer.len() < self.block_size as usize {
            return Err(Error::Validation(
                "Buffer is too small to contain a block".to_string(),
            ));
        }
        self.file
            .seek(SeekFrom::Start((block_index * self.block_size) as u64))
            .map_err(|_| Error::IO("Could not seek while writing block to img file".to_string()))?;
        self.file
            .write_all(buffer.deref_mut())
            .map_err(|_| Error::IO("Could not write block to img file".to_string()))?;

        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn total_blocks(&self) -> u32 {
        self.total_blocks
    }
}

// TODO: Add some sort of method to get a free inode number and block number
impl<D: BlockDevice> MyFS<D> {
    fn mount(mut device: D) -> Result<Self, Error> {
        // Read superblock
        let mut buffer = BlockBuffer::new();
        device.read_block(0, &mut buffer)?;
        let superblock = Superblock::try_from_bytes(&buffer.to_vec())?;

        // Validate magic number
        if superblock.magic_number != MAGIC_NUMBER {
            return Err(Error::Validation(
                "Disk is not a valid MyFS disk".to_string(),
            ));
        }

        // Load bitmaps
        device.read_block(superblock.inode_bitmap_start, &mut buffer)?;
        let inode_bitmap = Bitmap::new(&buffer);

        device.read_block(superblock.block_bitmap_start, &mut buffer)?;
        let block_bitmap = Bitmap::new(&buffer);

        device.read_block(superblock.inode_table_start, &mut buffer)?;
        let inodes = buffer
            .chunks(superblock.inode_size as usize)
            .take(superblock.inode_count as usize)
            .map(|chunk| Inode::try_from_bytes(chunk))
            .collect::<Result<_, _>>()?;

        Ok(MyFS {
            device,
            superblock,
            inode_bitmap,
            block_bitmap,
            inodes,
        })
    }

    fn format(device: &mut D) -> Result<(), Error> {
        // Replace all blocks with zeros
        let total_blocks = device.total_blocks();
        let mut buffer = BlockBuffer::new();
        for block_index in 0..total_blocks {
            device.write_block(block_index, &mut buffer)?;
        }

        // let mut buffer = vec![0u8; device.block_size() as usize];

        // Write superblock
        let super_block = Superblock {
            magic_number: MAGIC_NUMBER,
            version: 1,
            block_size: device.block_size(),
            total_blocks: TOTAL_BLOCKS,
            inode_count: INODE_COUNT,
            inode_size: INODE_SIZE,
            inode_bitmap_start: 1,
            block_bitmap_start: 2,
            inode_table_start: 3,
            data_block_start: 4,
        };
        buffer.copy_from_slice(super_block.to_bytes().as_slice());
        device.write_block(0, &mut buffer)?;

        // Write inode bitmap block
        // Leave 1 bit occupied for the root directory inode
        let inode_bitmap = Bitmap::create_and_occupy_first_n_bits(1);
        buffer.copy_from_slice(&inode_bitmap);
        device.write_block(1, &mut buffer)?;

        // Write block bitmap block
        // Leave 5 bits occupied; 4 for metadata blocks, 1 for root directory block
        let block_bitmap = Bitmap::create_and_occupy_first_n_bits(5);
        buffer.copy_from_slice(&block_bitmap);
        device.write_block(2, &mut buffer)?;

        // Write inode table
        let root_directory_inode = Inode::new(FileType::Directory, 0, 4);
        buffer.fill(0u8);
        buffer[0..INODE_SIZE as usize].copy_from_slice(root_directory_inode.to_bytes().as_slice());
        device.write_block(3, &mut buffer)?;

        Ok(())
    }

    fn resolve_path(&mut self, path: &str) -> Result<u32, Error> {
        let path_components = path
            .split('/')
            .filter(|&c| !c.is_empty())
            .collect::<Vec<&str>>();
        let mut buffer = BlockBuffer::new();
        // Start at the first data block (root directory block)
        let mut inode_number = 0;
        let mut current_dir_name = "~";

        'components: for component in path_components {
            let inode = &self.inodes[inode_number as usize];
            if inode.file_type != FileType::Directory {
                return Err(Error::Validation(format!(
                    "Path component {current_dir_name} is not a directory",
                )));
            }

            let block_index = inode.direct_block;
            self.device.read_block(block_index, &mut buffer)?;
            if buffer.is_empty() {
                return Err(Error::EntryNotFound {
                    entry: component.to_string(),
                    directory: current_dir_name.to_string(),
                });
            }
            let mut buffer_cursor = 0;

            while buffer_cursor < buffer.len() {
                let entry = DirectoryEntry::try_from_bytes(
                    &buffer[buffer_cursor..buffer_cursor + DIRECTORY_ENTRY_SIZE],
                )?;
                if entry.name.to_string() == component {
                    inode_number = entry.inode_number;
                    let inode_exists = self.inode_bitmap.is_bit_set(inode_number as usize);
                    if !inode_exists {
                        return Err(Error::Validation(format!(
                            "Inode for {} is empty",
                            component
                        )));
                    }
                    current_dir_name = component;
                    continue 'components;
                }
                buffer_cursor += DIRECTORY_ENTRY_SIZE
            }

            return Err(Error::EntryNotFound {
                entry: component.to_string(),
                directory: current_dir_name.to_string(),
            });
        }

        Ok(inode_number)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        BLOCK_SIZE, Bitmap, BlockBuffer, BlockDevice, BytesSerializable, DATA_BLOCK_START,
        DIRECTORY_ENTRY_SIZE, Directory, DirectoryEntry, Error, FILE_NAME_SIZE, Filename,
        INODE_BITMAP_BLOCK, INODE_COUNT, INODE_SIZE, INODE_TABLE_BLOCK, ImgFileDisk, MAGIC_NUMBER,
        Superblock, TOTAL_BLOCKS,
    };
    use crate::{FileType, Inode, MyFS};
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    #[test]
    fn serialize_superblock_to_bytes() {
        let superblock = Superblock {
            magic_number: MAGIC_NUMBER,
            version: 1,
            block_size: BLOCK_SIZE,
            total_blocks: 16,
            inode_count: 8,
            inode_size: 9,
            inode_bitmap_start: 1,
            block_bitmap_start: 2,
            inode_table_start: 3,
            data_block_start: 4,
        };

        let buffer = superblock.to_bytes();

        assert_eq!(buffer.len(), BLOCK_SIZE as usize);
        assert_eq!(buffer[0..4], MAGIC_NUMBER.to_le_bytes());
        assert_eq!(buffer[4..8], superblock.version.to_le_bytes());
        assert_eq!(buffer[8..12], superblock.block_size.to_le_bytes());
        assert_eq!(buffer[12..16], superblock.total_blocks.to_le_bytes());
        assert_eq!(buffer[16..20], superblock.inode_count.to_le_bytes());
        assert_eq!(buffer[20..24], superblock.inode_size.to_le_bytes());
        assert_eq!(buffer[24..28], superblock.inode_bitmap_start.to_le_bytes());
        assert_eq!(buffer[28..32], superblock.block_bitmap_start.to_le_bytes());
        assert_eq!(buffer[32..36], superblock.inode_table_start.to_le_bytes());
        assert_eq!(buffer[36..40], superblock.data_block_start.to_le_bytes());
    }

    #[test]
    fn deserialize_superblock_from_bytes() {
        let mut buffer = vec![0u8; BLOCK_SIZE as usize];
        let superblock = Superblock {
            magic_number: MAGIC_NUMBER,
            version: 1,
            block_size: BLOCK_SIZE,
            total_blocks: 16,
            inode_count: 8,
            inode_size: 9,
            inode_bitmap_start: 1,
            block_bitmap_start: 2,
            inode_table_start: 3,
            data_block_start: 4,
        };

        buffer[0..4].copy_from_slice(&superblock.magic_number.to_le_bytes());
        buffer[4..8].copy_from_slice(&superblock.version.to_le_bytes());
        buffer[8..12].copy_from_slice(&superblock.block_size.to_le_bytes());
        buffer[12..16].copy_from_slice(&superblock.total_blocks.to_le_bytes());
        buffer[16..20].copy_from_slice(&superblock.inode_count.to_le_bytes());
        buffer[20..24].copy_from_slice(&superblock.inode_size.to_le_bytes());
        buffer[24..28].copy_from_slice(&superblock.inode_bitmap_start.to_le_bytes());
        buffer[28..32].copy_from_slice(&superblock.block_bitmap_start.to_le_bytes());
        buffer[32..36].copy_from_slice(&superblock.inode_table_start.to_le_bytes());
        buffer[36..40].copy_from_slice(&superblock.data_block_start.to_le_bytes());

        let superblock_from_buffer = Superblock::try_from_bytes(&buffer).unwrap();

        assert_eq!(superblock_from_buffer.magic_number, superblock.magic_number);
        assert_eq!(superblock_from_buffer.version, superblock.version);
        assert_eq!(superblock_from_buffer.block_size, superblock.block_size);
        assert_eq!(superblock_from_buffer.total_blocks, superblock.total_blocks);
        assert_eq!(superblock_from_buffer.inode_count, superblock.inode_count);
        assert_eq!(superblock_from_buffer.inode_size, superblock.inode_size);
        assert_eq!(
            superblock_from_buffer.inode_bitmap_start,
            superblock.inode_bitmap_start
        );
        assert_eq!(
            superblock_from_buffer.block_bitmap_start,
            superblock.block_bitmap_start
        );
        assert_eq!(
            superblock_from_buffer.inode_table_start,
            superblock.inode_table_start
        );
        assert_eq!(
            superblock_from_buffer.data_block_start,
            superblock.data_block_start
        );
    }

    #[test]
    fn create_bitmap_and_occupy_first_n_bits() {
        let bitmap = Bitmap::create_and_occupy_first_n_bits(4);
        assert_eq!(bitmap[0], 0b1111);
        assert_eq!(bitmap[1], 0b0000);
    }

    #[test]
    fn print_filename_to_string() {
        let mut bytes = [0u8; FILE_NAME_SIZE];
        bytes[0..8].copy_from_slice(b"test.txt");

        let filename = Filename(bytes);

        assert_eq!(filename.to_string(), "test.txt");
    }

    #[test]
    fn new_filename() {
        let filename = Filename::new("test.txt".to_string());
        assert_eq!(filename[0..8].to_vec(), b"test.txt");
    }

    #[test]
    fn serialize_directory_entry_to_bytes() {
        let mut name = Filename([0u8; FILE_NAME_SIZE]);
        name[0..8].copy_from_slice(b"test.txt");

        let entry = DirectoryEntry {
            inode_number: 42,
            file_type: FileType::File,
            name_length: 8,
            name,
        };

        let bytes = entry.to_bytes();

        assert_eq!(bytes.len(), DIRECTORY_ENTRY_SIZE);
        assert_eq!(&bytes[0..4], &42u32.to_le_bytes());
        assert_eq!(bytes[4], FileType::File as u8);
        assert_eq!(bytes[5], 8);
        assert_eq!(&bytes[6..14], b"test.txt");
    }

    #[test]
    fn deserialize_directory_entry_from_bytes() {
        let mut bytes = vec![0u8; DIRECTORY_ENTRY_SIZE];
        bytes[0..4].copy_from_slice(&123u32.to_le_bytes());
        bytes[4] = FileType::Directory as u8;
        bytes[5] = 12;
        bytes[6..18].copy_from_slice(b"applications");

        let entry = DirectoryEntry::try_from_bytes(&bytes).unwrap();

        assert_eq!(entry.inode_number, 123);
        assert_eq!(entry.file_type, FileType::Directory);
        assert_eq!(entry.name_length, 12);
        assert_eq!(&entry.name[0..12], b"applications");
    }

    #[test]
    fn serialize_directory_to_bytes() {
        let mut name1 = Filename([0u8; FILE_NAME_SIZE]);
        name1[0..8].copy_from_slice(b"file.txt");
        let entry1 = DirectoryEntry {
            inode_number: 1,
            file_type: FileType::File,
            name_length: 8,
            name: name1,
        };

        let mut name2 = Filename([0u8; FILE_NAME_SIZE]);
        name2[0..3].copy_from_slice(b"dir");
        let entry2 = DirectoryEntry {
            inode_number: 2,
            file_type: FileType::Directory,
            name_length: 3,
            name: name2,
        };

        let directory = Directory(vec![entry1, entry2]);
        let bytes = directory.to_bytes();

        assert_eq!(bytes.len(), DIRECTORY_ENTRY_SIZE * 2);

        // Check first entry
        assert_eq!(&bytes[0..4], &1u32.to_le_bytes());
        assert_eq!(bytes[4], FileType::File as u8);
        assert_eq!(bytes[5], 8);
        assert_eq!(&bytes[6..14], b"file.txt");

        // Check second entry
        let offset = DIRECTORY_ENTRY_SIZE;
        assert_eq!(&bytes[offset..offset + 4], &2u32.to_le_bytes());
        assert_eq!(bytes[offset + 4], FileType::Directory as u8);
        assert_eq!(bytes[offset + 5], 3);
        assert_eq!(&bytes[offset + 6..offset + 9], b"dir");
    }

    #[test]
    fn deserialize_directory_from_bytes() {
        let mut bytes = vec![0u8; DIRECTORY_ENTRY_SIZE * 2];

        // First entry
        bytes[0..4].copy_from_slice(&10u32.to_le_bytes());
        bytes[4] = FileType::File as u8;
        bytes[5] = 9;
        bytes[6..15].copy_from_slice(b"test1.txt");

        // Second entry
        let offset = DIRECTORY_ENTRY_SIZE;
        bytes[offset..offset + 4].copy_from_slice(&20u32.to_le_bytes());
        bytes[offset + 4] = FileType::Directory as u8;
        bytes[offset + 5] = 9;
        bytes[offset + 6..offset + 15].copy_from_slice(b"test2.txt");

        let directory = Directory::try_from_bytes(&bytes).unwrap();

        assert_eq!(directory.len(), 2);
        assert_eq!(directory[0].inode_number, 10);
        assert_eq!(directory[0].file_type, FileType::File);
        assert_eq!(directory[0].name_length, 9);
        assert_eq!(&directory[0].name[0..9], b"test1.txt");

        assert_eq!(directory[1].inode_number, 20);
        assert_eq!(directory[1].file_type, FileType::Directory);
        assert_eq!(directory[1].name_length, 9);
        assert_eq!(&directory[1].name[0..9], b"test2.txt");
    }

    #[test]
    fn img_file_disk_open_valid_file() {
        let path = Path::new("test_disk.img");
        fs::File::create(path).unwrap();

        let result = ImgFileDisk::open(path);
        assert!(result.is_ok());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn img_file_disk_open_file_not_found() {
        let path = Path::new("nonexistent.img");

        let result = ImgFileDisk::open(path);

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            Error::IO("Disk file not found".to_string())
        );
    }

    #[test]
    fn img_file_disk_open_invalid_extension() {
        let path = Path::new("test_disk.txt");
        fs::File::create(path).unwrap();

        let result = ImgFileDisk::open(path);
        assert!(result.is_err());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn img_file_disk_read_block() {
        let path = Path::new("test_read.img");
        let mut file = fs::File::create(path).unwrap();
        let mut data = vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize];
        data[BLOCK_SIZE as usize] = 0xAB;
        data[BLOCK_SIZE as usize + 1] = 0xCD;
        file.write_all(&data).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        let mut buffer = BlockBuffer::new();
        let result = disk.read_block(1, &mut buffer);

        assert!(result.is_ok());
        assert_eq!(buffer[0], 0xAB);
        assert_eq!(buffer[1], 0xCD);

        fs::remove_file(path).unwrap();
    }

    // TODO: This test is now obsolete because BlockBuffer type eliminates the possibility of too small or too big buffers.
    // #[test]
    // fn img_file_disk_read_block_buffer_too_small() {
    //     let path = Path::new("test_read_small_buffer.img");
    //     let mut file = fs::File::create(path).unwrap();
    //     file.write_all(&vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize])
    //         .unwrap();
    //     drop(file);
    //
    //     let mut disk = ImgFileDisk::open(path).unwrap();
    //     let mut buffer = BlockBuffer::new();
    //     let result = disk.read_block(0, &mut buffer);
    //
    //     assert!(result.is_err());
    //     assert_eq!(
    //         result.err().unwrap(),
    //         Error::Validation("Buffer is too small to contain a block".to_string())
    //     );
    //
    //     fs::remove_file(path).unwrap();
    // }

    #[test]
    fn img_file_disk_write_block() {
        let path = Path::new("test_write.img");
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize])
            .unwrap();
        drop(file);

        let mut disk = ImgFileDisk::open(path).unwrap();
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut buffer = BlockBuffer::new();
        buffer[0..4].copy_from_slice(&data);

        let write_result = disk.write_block(2, &mut buffer);
        buffer.fill(0);
        assert!(write_result.is_ok());

        disk.read_block(2, &mut buffer).unwrap();
        assert_eq!(buffer[0..4], data[..]);

        fs::remove_file(path).unwrap();
    }

    // TODO: This test is now obsolete because BlockBuffer type eliminates the possibility of too small or too big buffers.
    // #[test]
    // fn img_file_disk_write_block_buffer_too_small() {
    //     let path = Path::new("test_write_small_buffer.img");
    //     let mut file = fs::File::create(path).unwrap();
    //     file.write_all(&vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize])
    //         .unwrap();
    //     drop(file);
    //
    //     let mut disk = ImgFileDisk::open(path).unwrap();
    //     let buffer = BlockBuffer([0u8; (BLOCK_SIZE - 1) as usize]);
    //     let result = disk.write_block(0, &mut buffer);
    //
    //     assert!(result.is_err());
    //     assert_eq!(
    //         result.err().unwrap(),
    //         Error::Validation("Buffer is too small to contain a block".to_string())
    //     );
    //
    //     fs::remove_file(path).unwrap();
    // }

    #[test]
    fn img_file_disk_block_size() {
        let path = Path::new("test_blocksize.img");
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize])
            .unwrap();
        drop(file);

        let disk = ImgFileDisk::open(path).unwrap();
        assert_eq!(disk.block_size(), BLOCK_SIZE);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn img_file_disk_total_blocks() {
        let path = Path::new("test_total_blocks.img");
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize])
            .unwrap();
        drop(file);

        let disk = ImgFileDisk::open(path).unwrap();
        assert_eq!(disk.total_blocks(), TOTAL_BLOCKS);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_format_clears_all_blocks() {
        let path = Path::new("test_format_clear.img");
        let mut file = fs::File::create(path).unwrap();
        // Write data into all blocks in the file
        file.write_all(&vec![0xFF; (BLOCK_SIZE * TOTAL_BLOCKS) as usize])
            .unwrap();
        drop(file);

        let mut disk = ImgFileDisk::open(path).unwrap();
        let mut buffer = BlockBuffer::new();

        // Ensure the data exists in the file
        for block_index in 0..TOTAL_BLOCKS {
            disk.read_block(block_index, &mut buffer).unwrap();
        }
        assert_eq!(buffer.0, [0xFFu8; BLOCK_SIZE as usize]);

        // Format the disk
        MyFS::format(&mut disk).unwrap();

        // Ensure the data is cleared after formatting
        for block_index in 0..TOTAL_BLOCKS {
            disk.read_block(block_index, &mut buffer).unwrap();
        }
        assert_eq!(buffer.0, [0u8; BLOCK_SIZE as usize]);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_format_writes_superblock() {
        let path = Path::new("test_format_superblock.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();

        let mut buffer = BlockBuffer::new();
        disk.read_block(0, &mut buffer).unwrap();

        let superblock = Superblock::try_from_bytes(&buffer.to_vec()).unwrap();
        assert_eq!(superblock.magic_number, MAGIC_NUMBER);
        assert_eq!(superblock.version, 1);
        assert_eq!(superblock.block_size, BLOCK_SIZE);
        assert_eq!(superblock.total_blocks, TOTAL_BLOCKS);
        assert_eq!(superblock.inode_count, INODE_COUNT);
        assert_eq!(superblock.inode_size, INODE_SIZE);
        assert_eq!(superblock.inode_bitmap_start, 1);
        assert_eq!(superblock.block_bitmap_start, 2);
        assert_eq!(superblock.inode_table_start, 3);
        assert_eq!(superblock.data_block_start, 4);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_format_writes_inode_bitmap() {
        let path = Path::new("test_format_inode_bitmap.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();

        let mut buffer = BlockBuffer::new();
        disk.read_block(1, &mut buffer).unwrap();

        let inode_bitmap = Bitmap::new(&buffer);
        assert!(inode_bitmap.is_bit_set(0));
        assert!(!inode_bitmap.is_bit_set(1));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_format_writes_data_bitmap() {
        let path = Path::new("test_format_data_bitmap.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();

        let mut buffer = BlockBuffer::new();
        disk.read_block(2, &mut buffer).unwrap();

        let data_bitmap = Bitmap::new(&buffer);
        assert!(data_bitmap.is_bit_set(0));
        assert!(data_bitmap.is_bit_set(1));
        assert!(data_bitmap.is_bit_set(2));
        assert!(data_bitmap.is_bit_set(3));
        assert!(data_bitmap.is_bit_set(4));
        assert!(!data_bitmap.is_bit_set(5));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_format_writes_root_inode() {
        let path = Path::new("test_format_root_inode.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();

        let mut buffer = BlockBuffer::new();
        disk.read_block(3, &mut buffer).unwrap();

        let root_inode = Inode::try_from_bytes(&buffer[0..INODE_SIZE as usize]).unwrap();
        assert_eq!(root_inode.file_type, FileType::Directory);
        assert_eq!(root_inode.size, 0);
        assert_eq!(root_inode.direct_block, 4);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_format_succeeds() {
        let path = Path::new("test_format_success.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        let result = MyFS::format(&mut disk);

        assert!(result.is_ok());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_mount_invalid_magic_number() {
        let path = Path::new("test_mount_invalid_magic.img");
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize])
            .unwrap();
        drop(file);

        let disk = ImgFileDisk::open(path).unwrap();
        let result = MyFS::mount(disk);

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            Error::Validation("Disk is not a valid MyFS disk".to_string())
        );

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_mount_reads_superblock_correctly() {
        let path = Path::new("test_mount_superblock.img");
        let mut file = fs::File::create(path).unwrap();

        // Write superblock manually
        let mut data = vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize];
        data[0..4].copy_from_slice(&MAGIC_NUMBER.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // version
        data[8..12].copy_from_slice(&BLOCK_SIZE.to_le_bytes());
        data[12..16].copy_from_slice(&TOTAL_BLOCKS.to_le_bytes());
        data[16..20].copy_from_slice(&INODE_COUNT.to_le_bytes());
        data[20..24].copy_from_slice(&INODE_SIZE.to_le_bytes());
        data[24..28].copy_from_slice(&1u32.to_le_bytes()); // inode_bitmap_start
        data[28..32].copy_from_slice(&2u32.to_le_bytes()); // block_bitmap_start
        data[32..36].copy_from_slice(&3u32.to_le_bytes()); // inode_table_start
        data[36..40].copy_from_slice(&4u32.to_le_bytes()); // data_block_start

        file.write_all(&data).unwrap();
        drop(file);

        let disk = ImgFileDisk::open(path).unwrap();
        let fs = MyFS::mount(disk).unwrap();
        assert_eq!(fs.superblock.magic_number, MAGIC_NUMBER);
        assert_eq!(fs.superblock.version, 1);
        assert_eq!(fs.superblock.block_size, BLOCK_SIZE);
        assert_eq!(fs.superblock.total_blocks, TOTAL_BLOCKS);
        assert_eq!(fs.superblock.inode_count, INODE_COUNT);
        assert_eq!(fs.superblock.inode_size, INODE_SIZE);
        assert_eq!(fs.superblock.inode_bitmap_start, 1);
        assert_eq!(fs.superblock.block_bitmap_start, 2);
        assert_eq!(fs.superblock.inode_table_start, 3);
        assert_eq!(fs.superblock.data_block_start, 4);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_mount_loads_inode_bitmap() {
        let path = Path::new("test_mount_inode_bitmap.img");
        let mut file = fs::File::create(path).unwrap();

        // Write superblock and inode bitmap manually
        let mut data = vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize];
        data[0..4].copy_from_slice(&MAGIC_NUMBER.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..12].copy_from_slice(&BLOCK_SIZE.to_le_bytes());
        data[12..16].copy_from_slice(&TOTAL_BLOCKS.to_le_bytes());
        data[16..20].copy_from_slice(&INODE_COUNT.to_le_bytes());
        data[20..24].copy_from_slice(&INODE_SIZE.to_le_bytes());
        data[24..28].copy_from_slice(&1u32.to_le_bytes());
        data[28..32].copy_from_slice(&2u32.to_le_bytes());
        data[32..36].copy_from_slice(&3u32.to_le_bytes());
        data[36..40].copy_from_slice(&4u32.to_le_bytes());

        // Write inode bitmap at block 1 with first bit set
        data[BLOCK_SIZE as usize] = 0b00000001;

        file.write_all(&data).unwrap();
        drop(file);

        let disk = ImgFileDisk::open(path).unwrap();
        let fs = MyFS::mount(disk).unwrap();
        assert!(fs.inode_bitmap.is_bit_set(0));
        assert!(!fs.inode_bitmap.is_bit_set(1));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_mount_loads_block_bitmap() {
        let path = Path::new("test_mount_block_bitmap.img");
        let mut file = fs::File::create(path).unwrap();

        // Write superblock and block bitmap manually
        let mut data = vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize];
        data[0..4].copy_from_slice(&MAGIC_NUMBER.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..12].copy_from_slice(&BLOCK_SIZE.to_le_bytes());
        data[12..16].copy_from_slice(&TOTAL_BLOCKS.to_le_bytes());
        data[16..20].copy_from_slice(&INODE_COUNT.to_le_bytes());
        data[20..24].copy_from_slice(&INODE_SIZE.to_le_bytes());
        data[24..28].copy_from_slice(&1u32.to_le_bytes());
        data[28..32].copy_from_slice(&2u32.to_le_bytes());
        data[32..36].copy_from_slice(&3u32.to_le_bytes());
        data[36..40].copy_from_slice(&4u32.to_le_bytes());

        // Write block bitmap at block 2 with first 5 bits set
        data[(2 * BLOCK_SIZE) as usize] = 0b00011111;

        file.write_all(&data).unwrap();
        drop(file);

        let disk = ImgFileDisk::open(path).unwrap();
        let fs = MyFS::mount(disk).unwrap();
        assert!(fs.block_bitmap.is_bit_set(0));
        assert!(fs.block_bitmap.is_bit_set(1));
        assert!(fs.block_bitmap.is_bit_set(2));
        assert!(fs.block_bitmap.is_bit_set(3));
        assert!(fs.block_bitmap.is_bit_set(4));
        assert!(!fs.block_bitmap.is_bit_set(5));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_mount_succeeds() {
        let path = Path::new("test_mount_success.img");
        let mut file = fs::File::create(path).unwrap();

        // Write superblock manually
        let mut data = vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize];
        data[0..4].copy_from_slice(&MAGIC_NUMBER.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // version
        data[8..12].copy_from_slice(&BLOCK_SIZE.to_le_bytes());
        data[12..16].copy_from_slice(&TOTAL_BLOCKS.to_le_bytes());
        data[16..20].copy_from_slice(&INODE_COUNT.to_le_bytes());
        data[20..24].copy_from_slice(&INODE_SIZE.to_le_bytes());
        data[24..28].copy_from_slice(&1u32.to_le_bytes()); // inode_bitmap_start
        data[28..32].copy_from_slice(&2u32.to_le_bytes()); // block_bitmap_start
        data[32..36].copy_from_slice(&3u32.to_le_bytes()); // inode_table_start
        data[36..40].copy_from_slice(&4u32.to_le_bytes()); // data_block_start

        file.write_all(&data).unwrap();
        drop(file);

        let disk = ImgFileDisk::open(path).unwrap();
        let result = MyFS::mount(disk);
        assert!(result.is_ok());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_resolve_path_root() {
        let path = Path::new("test_resolve_root.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();
        let mut fs = MyFS::mount(disk).unwrap();

        let result = fs.resolve_path("/");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_resolve_path_single_level() {
        let path = Path::new("test_resolve_single_level.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();
        let mut fs = MyFS::mount(disk).unwrap();
        let mut block_buffer = BlockBuffer::new();

        // Create a directory entry in root
        let name = Filename::new("dir".to_string());
        let entry = DirectoryEntry {
            inode_number: 1,
            file_type: FileType::Directory,
            name_length: 3,
            name,
        };
        let directory = Directory(vec![entry]);
        let dir_bytes = directory.to_bytes();
        block_buffer[0..dir_bytes.len()].copy_from_slice(&dir_bytes);
        fs.device.write_block(4, &mut block_buffer).unwrap();
        block_buffer.fill(0);

        // Set inode 1 in bitmap
        fs.inode_bitmap.set_bit(1);
        block_buffer.copy_from_slice(&fs.inode_bitmap);
        fs.device.write_block(1, &mut block_buffer).unwrap();
        block_buffer.fill(0);

        // Create inode 1
        let inode = Inode::new(FileType::Directory, 0, 5);
        fs.inodes.insert(1, inode);
        block_buffer[INODE_SIZE as usize..(2 * INODE_SIZE as usize)]
            .copy_from_slice(&inode.to_bytes());
        fs.device.write_block(3, &mut block_buffer).unwrap();

        // Reload filesystem
        drop(fs);
        let disk = ImgFileDisk::open(path).unwrap();
        let mut fs = MyFS::mount(disk).unwrap();

        let result = fs.resolve_path("/dir");

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_resolve_path_multi_level() {
        let path = Path::new("test_resolve_multi_level.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();
        let mut fs = MyFS::mount(disk).unwrap();

        // Create first level directory entry in root (inode 0, block 4)
        let name1 = Filename::new("dir".to_string());
        let entry1 = DirectoryEntry {
            inode_number: 1,
            file_type: FileType::Directory,
            name_length: 3,
            name: name1,
        };
        let directory1 = Directory(vec![entry1]);
        let dir_bytes1 = directory1.to_bytes();
        let mut buffer = BlockBuffer::new();
        buffer[0..dir_bytes1.len()].copy_from_slice(&dir_bytes1);
        fs.device.write_block(4, &mut buffer).unwrap();

        // Create second level directory entry (inode 1, block 5)
        let name2 = Filename::new("subdir".to_string());
        let entry2 = DirectoryEntry {
            inode_number: 2,
            file_type: FileType::Directory,
            name_length: 6,
            name: name2,
        };
        let directory2 = Directory(vec![entry2]);
        let dir_bytes2 = directory2.to_bytes();
        buffer.fill(0);
        buffer[0..dir_bytes2.len()].copy_from_slice(&dir_bytes2);
        fs.device.write_block(5, &mut buffer).unwrap();

        // Set inodes in bitmap
        fs.inode_bitmap.set_bit(1);
        fs.inode_bitmap.set_bit(2);
        buffer.fill(0);
        buffer.copy_from_slice(&fs.inode_bitmap);
        fs.device.write_block(1, &mut buffer).unwrap();

        // Set blocks in bitmap
        fs.block_bitmap.set_bit(5);
        fs.block_bitmap.set_bit(6);
        buffer.fill(0);
        buffer.copy_from_slice(&fs.block_bitmap);
        fs.device.write_block(2, &mut buffer).unwrap();

        // Create inodes
        let inode1 = Inode::new(FileType::Directory, 0, 5);
        let inode2 = Inode::new(FileType::Directory, 0, 6);
        buffer.fill(0);
        buffer[INODE_SIZE as usize..(2 * INODE_SIZE as usize)].copy_from_slice(&inode1.to_bytes());
        buffer[(2 * INODE_SIZE as usize)..(3 * INODE_SIZE as usize)]
            .copy_from_slice(&inode2.to_bytes());
        fs.device.write_block(3, &mut buffer).unwrap();

        // Reload filesystem
        drop(fs);
        let disk = ImgFileDisk::open(path).unwrap();
        let mut fs = MyFS::mount(disk).unwrap();

        let result = fs.resolve_path("/dir/subdir");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_resolve_path_nonexistent_directory() {
        let path = Path::new("test_resolve_nonexistent_dir.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();
        let mut fs = MyFS::mount(disk).unwrap();

        let result = fs.resolve_path("/nonexistent");
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            Error::EntryNotFound { entry: "nonexistent".to_string(), directory: "~".to_string() }
        );

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_resolve_path_nonexistent_file_in_existing_directory() {
        let path = Path::new("test_resolve_nonexistent_file.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();
        let mut fs = MyFS::mount(disk).unwrap();

        // Create a directory entry in root
        let name = Filename::new("dir".to_string());
        let entry = DirectoryEntry {
            inode_number: 1,
            file_type: FileType::Directory,
            name_length: name.len() as u8,
            name,
        };
        let directory = Directory(vec![entry]);
        let dir_bytes = directory.to_bytes();
        let mut buffer = BlockBuffer::new();
        buffer[0..dir_bytes.len()].copy_from_slice(&dir_bytes);
        fs.device
            .write_block(DATA_BLOCK_START, &mut buffer)
            .unwrap();
        buffer.fill(0);

        // Set inode 1 in bitmap
        fs.inode_bitmap.set_bit(1);
        buffer.copy_from_slice(&fs.inode_bitmap);
        fs.device
            .write_block(INODE_BITMAP_BLOCK, &mut buffer)
            .unwrap();
        buffer.fill(0);

        // Create inode 1
        let inodes = &mut fs.inodes;
        let inode = Inode::new(FileType::Directory, 0, 5);
        inodes.insert(1, inode);
        let inodes_bytes = inodes.iter().fold(vec![], |mut byte_array, inode| {
            byte_array.extend(inode.to_bytes());
            byte_array
        });
        buffer[0..inodes_bytes.len()].copy_from_slice(&inodes_bytes);
        // buffer[INODE_SIZE as usize..(2 * INODE_SIZE as usize)].copy_from_slice(&inodes_bytes);
        fs.device
            .write_block(INODE_TABLE_BLOCK, &mut buffer)
            .unwrap();
        buffer.fill(0);

        // Reload filesystem
        drop(fs);
        let disk = ImgFileDisk::open(path).unwrap();
        let mut fs = MyFS::mount(disk).unwrap();

        let result = fs.resolve_path("/dir/nonexistent");
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            Error::EntryNotFound {
                entry: "nonexistent".to_string(),
                directory: "dir".to_string()
            }
        );

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_resolve_path_with_empty_components() {
        let path = Path::new("test_resolve_empty_components.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();
        let mut fs = MyFS::mount(disk).unwrap();

        // Create a directory entry in root
        let name = Filename::new("dir".to_string());
        let entry = DirectoryEntry {
            inode_number: 1,
            file_type: FileType::Directory,
            name_length: name.len() as u8,
            name,
        };
        let directory = Directory(vec![entry]);
        let dir_bytes = directory.to_bytes();
        let mut buffer = BlockBuffer::new();
        buffer[0..dir_bytes.len()].copy_from_slice(&dir_bytes);
        fs.device.write_block(4, &mut buffer).unwrap();

        // Set inode 1 in bitmap
        fs.inode_bitmap.set_bit(1);
        buffer.fill(0);
        buffer.copy_from_slice(&fs.inode_bitmap);
        fs.device.write_block(1, &mut buffer).unwrap();

        // Create inode 1
        let inode = Inode::new(FileType::Directory, 0, 5);
        buffer.fill(0);
        buffer[INODE_SIZE as usize..(2 * INODE_SIZE as usize)].copy_from_slice(&inode.to_bytes());
        fs.device.write_block(3, &mut buffer).unwrap();

        // Reload filesystem
        drop(fs);
        let disk = ImgFileDisk::open(path).unwrap();
        let mut fs = MyFS::mount(disk).unwrap();

        let result = fs.resolve_path("//dir//");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_resolve_path_inode_not_set_in_bitmap() {
        let path = Path::new("test_resolve_inode_not_set.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();
        let mut fs = MyFS::mount(disk).unwrap();

        // Create a directory entry in root pointing to inode 1
        let name = Filename::new("dir".to_string());
        let entry = DirectoryEntry {
            inode_number: 1,
            file_type: FileType::Directory,
            name_length: name.len() as u8,
            name,
        };
        let directory = Directory(vec![entry]);
        let dir_bytes = directory.to_bytes();
        let mut buffer = BlockBuffer::new();
        buffer[0..dir_bytes.len()].copy_from_slice(&dir_bytes);
        fs.device
            .write_block(DATA_BLOCK_START, &mut buffer)
            .unwrap();

        // Do NOT set inode 1 in bitmap

        // Reload filesystem
        drop(fs);
        let disk = ImgFileDisk::open(path).unwrap();
        let mut fs = MyFS::mount(disk).unwrap();

        let result = fs.resolve_path("/dir");
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            Error::Validation("Inode for dir is empty".to_string())
        );

        fs::remove_file(path).unwrap();
    }
}
