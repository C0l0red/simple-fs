extern crate core;

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
const BLOCK_SIZE: u32 = 512;
const TOTAL_BLOCKS: u32 = 16;

#[derive(Debug, PartialEq)]
enum Error {
    Validation(String),
    IO(String),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err.to_string())
    }
}

trait BlockDevice {
    fn read_block(&mut self, block_index: u32, buffer: &mut [u8]) -> Result<(), Error>;
    fn write_block(&mut self, block_index: u32, data: &[u8]) -> Result<(), Error>;
    fn block_size(&self) -> u32;
    fn total_blocks(&self) -> u32;
}

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
}

struct Superblock {
    magic_number: u32,
    version: u32,
    block_size: u32,
    total_blocks: u32,
    inode_count: u32,
    inode_size: u32,
    inode_bitmap_start: u32,
    data_bitmap_start: u32,
    inode_table_start: u32,
    data_block_start: u32,
}

struct Bitmap(Vec<u8>);

#[derive(Copy, Clone)]
struct Inode {
    kind: InodeKind,
    size: u32,
    direct_block: u32,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
enum InodeKind {
    File = 0u8,
    Directory = 1u8,
}

struct DirectoryEntry {
    inode: u32,
    name_len: u8,
    name: [u8; 256],
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
    fn new() -> Self {
        Self(vec![0u8; BLOCK_SIZE as usize])
    }

    fn create_and_occupy_first_n_bits(occupied_offset: usize) -> Self {
        let mut bitmap = Self::new();
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

impl TryFrom<u8> for InodeKind {
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
    fn new(kind: InodeKind, size: u32, direct_block: u32) -> Self {
        Self {
            kind,
            size,
            direct_block,
        }
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
        let mut buffer: Vec<u8> = vec![0u8; INODE_SIZE as usize];

        buffer[0] = self.kind as u8;
        buffer[1..5].copy_from_slice(&self.size.to_le_bytes());
        buffer[5..9].copy_from_slice(&self.direct_block.to_le_bytes());

        buffer
    }

    fn try_from_bytes(buffer: &[u8]) -> Result<Self, Error> {
        if buffer.len() < 9 {
            return Err(Error::Validation(
                "Buffer is too short to contain an Inode".to_string(),
            ));
        }

        Ok(Inode {
            kind: InodeKind::try_from(buffer[0])?,
            size: Self::bytes_to_u32(&buffer[1..5])?,
            direct_block: Self::bytes_to_u32(&buffer[5..9])?,
        })
    }
}

impl BytesSerializable for Superblock {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![0u8; BLOCK_SIZE as usize];

        buffer[0..4].copy_from_slice(&self.magic_number.to_le_bytes());
        buffer[4..8].copy_from_slice(&self.version.to_le_bytes());
        buffer[8..12].copy_from_slice(&self.block_size.to_le_bytes());
        buffer[12..16].copy_from_slice(&self.total_blocks.to_le_bytes());
        buffer[16..20].copy_from_slice(&self.inode_count.to_le_bytes());
        buffer[20..24].copy_from_slice(&self.inode_size.to_le_bytes());
        buffer[24..28].copy_from_slice(&self.inode_bitmap_start.to_le_bytes());
        buffer[28..32].copy_from_slice(&self.data_bitmap_start.to_le_bytes());
        buffer[32..36].copy_from_slice(&self.inode_table_start.to_le_bytes());
        buffer[36..40].copy_from_slice(&self.data_block_start.to_le_bytes());

        buffer
    }

    fn try_from_bytes(buffer: &[u8]) -> Result<Self, Error> {
        if buffer.len() < BLOCK_SIZE as usize {
            return Err(Error::Validation(
                "Buffer is too short to contain a Superblock".to_string(),
            ));
        }

        Ok(Superblock {
            magic_number: Self::bytes_to_u32(&buffer[0..4])?,
            version: Self::bytes_to_u32(&buffer[4..8])?,
            block_size: Self::bytes_to_u32(&buffer[8..12])?,
            total_blocks: Self::bytes_to_u32(&buffer[12..16])?,
            inode_count: Self::bytes_to_u32(&buffer[16..20])?,
            inode_size: Self::bytes_to_u32(&buffer[20..24])?,
            inode_bitmap_start: Self::bytes_to_u32(&buffer[24..28])?,
            data_bitmap_start: Self::bytes_to_u32(&buffer[28..32])?,
            inode_table_start: Self::bytes_to_u32(&buffer[32..36])?,
            data_block_start: Self::bytes_to_u32(&buffer[36..40])?,
        })
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
    fn read_block(&mut self, block_index: u32, buffer: &mut [u8]) -> Result<(), Error> {
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
            .read_exact(buffer)
            .map_err(|_| Error::IO("Could not read block from img file".to_string()))?;

        Ok(())
    }

    fn write_block(&mut self, block_index: u32, buffer: &[u8]) -> Result<(), Error> {
        if buffer.len() < self.block_size as usize {
            return Err(Error::Validation(
                "Buffer is too small to contain a block".to_string(),
            ));
        }
        self.file
            .seek(SeekFrom::Start((block_index * self.block_size) as u64))
            .map_err(|_| Error::IO("Could not seek while writing block to img file".to_string()))?;
        self.file
            .write_all(buffer)
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

impl<D: BlockDevice> MyFS<D> {
    fn mount(mut device: D) -> Result<Self, Error> {
        // read superblock
        // validate magic
        // load bitmaps
        // construct MyFS
        todo!()
    }

    fn format(device: &mut D) -> Result<(), Error> {
        // Replace all blocks with zeros
        let total_blocks = device.total_blocks();
        for block_index in 0..total_blocks {
            device.write_block(
                block_index,
                vec![0u8; device.block_size() as usize].as_slice(),
            )?;
        }

        let mut buffer = vec![0u8; device.block_size() as usize];

        // Write superblock
        let super_block = Superblock {
            magic_number: MAGIC_NUMBER,
            version: 1,
            block_size: device.block_size(),
            total_blocks: TOTAL_BLOCKS,
            inode_count: INODE_COUNT,
            inode_size: INODE_SIZE,
            inode_bitmap_start: 1,
            data_bitmap_start: 2,
            inode_table_start: 3,
            data_block_start: 4,
        };
        buffer.copy_from_slice(super_block.to_bytes().as_slice());
        device.write_block(0, buffer.as_slice())?;

        // Write bitmap blocks
        // Leave 1 bit occupied for the root directory inode
        let inode_bitmap = Bitmap::create_and_occupy_first_n_bits(1);
        buffer.copy_from_slice(&inode_bitmap);
        device.write_block(1, buffer.as_slice())?;

        // Write bitmap blocks
        // Leave 5 bits occupied; 4 for metadata blocks, 1 for root directory block
        let block_bitmap = Bitmap::create_and_occupy_first_n_bits(5);
        buffer.copy_from_slice(&block_bitmap);
        device.write_block(2, buffer.as_slice())?;

        // Write inode table
        let root_directory_inode = Inode::new(InodeKind::Directory, 0, 4);
        buffer.fill(0u8);
        buffer[0..INODE_SIZE as usize].copy_from_slice(root_directory_inode.to_bytes().as_slice());
        device.write_block(3, buffer.as_slice())?;

        Ok(())
    }
}

// impl ImgFileDisk {
//     fn validate_img_file(&self, block_size: u32, magic_number: u32) -> Result<(), Error> {
//         let mut buffer = vec![0u8; block_size as usize];
//         let mut file = File::open(&self.file)
//             .map_err(|_| Error::Validation("Could not open disk file".to_string()))?;
//
//         let bytes_read = file
//             .read(buffer.as_mut_slice())
//             .map_err(|_| Error::Validation("Could not read disk file".to_string()))?;
//         if bytes_read == 0 {
//             return Self::format_disk(file, block_size, magic_number);
//         }
//         if bytes_read != block_size as usize {
//             return Err(Error::Validation("File is too small".to_string()));
//         }
//
//         let super_block = Superblock::try_from_bytes(&buffer)
//             .map_err(|_| Error::Validation("Could not read superblock".to_string()))?;
//
//         if super_block.magic_number != magic_number {
//             return Err(Error::Validation(
//                 "File is not a valid Disk for this file system".to_string(),
//             ));
//         }
//
//         Ok(())
//     }
// }

#[cfg(test)]
mod tests {
    use crate::{
        BLOCK_SIZE, Bitmap, BlockDevice, BytesSerializable, Error, INODE_COUNT, INODE_SIZE,
        ImgFileDisk, MAGIC_NUMBER, Superblock, TOTAL_BLOCKS,
    };
    use crate::{MyFS, Inode, InodeKind};
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    #[test]
    fn serialize_superblock_to_bytes() {
        let superblock = Superblock {
            magic_number: MAGIC_NUMBER,
            version: 1,
            block_size: 512,
            total_blocks: 16,
            inode_count: 8,
            inode_size: 9,
            inode_bitmap_start: 1,
            data_bitmap_start: 2,
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
        assert_eq!(buffer[28..32], superblock.data_bitmap_start.to_le_bytes());
        assert_eq!(buffer[32..36], superblock.inode_table_start.to_le_bytes());
        assert_eq!(buffer[36..40], superblock.data_block_start.to_le_bytes());
    }

    #[test]
    fn deserialize_superblock_from_bytes() {
        let mut buffer: Vec<u8> = vec![
            83, 70, 89, 77, 1, 0, 0, 0, 0, 2, 0, 0, 16, 0, 0, 0, 8, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0,
            0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0,
        ];
        buffer.resize(BLOCK_SIZE as usize, 0u8);
        let superblock = Superblock::try_from_bytes(&buffer).unwrap();

        assert_eq!(superblock.magic_number, MAGIC_NUMBER);
        assert_eq!(superblock.version, 1);
        assert_eq!(superblock.block_size, BLOCK_SIZE);
        assert_eq!(superblock.total_blocks, TOTAL_BLOCKS);
        assert_eq!(superblock.inode_count, INODE_COUNT);
        assert_eq!(superblock.inode_size, INODE_SIZE);
        assert_eq!(superblock.inode_bitmap_start, 1);
        assert_eq!(superblock.data_bitmap_start, 2);
        assert_eq!(superblock.inode_table_start, 3);
        assert_eq!(superblock.data_block_start, 4);
    }

    #[test]
    fn create_bitmap_and_occupy_first_n_bits() {
        let bitmap = Bitmap::create_and_occupy_first_n_bits(4);
        assert_eq!(bitmap[0], 0b1111);
        assert_eq!(bitmap[1], 0b0000);
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
        let mut buffer = vec![0u8; BLOCK_SIZE as usize];
        let result = disk.read_block(1, &mut buffer);

        assert!(result.is_ok());
        assert_eq!(buffer[0], 0xAB);
        assert_eq!(buffer[1], 0xCD);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn img_file_disk_read_block_buffer_too_small() {
        let path = Path::new("test_read_small_buffer.img");
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize])
            .unwrap();
        drop(file);

        let mut disk = ImgFileDisk::open(path).unwrap();
        let mut buffer = vec![0u8; (BLOCK_SIZE - 1) as usize];
        let result = disk.read_block(0, &mut buffer);

        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), Error::Validation("Buffer is too small to contain a block".to_string()));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn img_file_disk_write_block() {
        let path = Path::new("test_write.img");
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize])
            .unwrap();
        drop(file);

        let mut disk = ImgFileDisk::open(path).unwrap();
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut buffer = vec![0u8; BLOCK_SIZE as usize];
        buffer[0..4].copy_from_slice(&data);

        let write_result = disk.write_block(2, &buffer);
        assert!(write_result.is_ok());

        let mut read_buffer = vec![0u8; BLOCK_SIZE as usize];
        disk.read_block(2, &mut read_buffer).unwrap();
        assert_eq!(read_buffer[0..4], data[..]);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn img_file_disk_write_block_buffer_too_small() {
        let path = Path::new("test_write_small_buffer.img");
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![0u8; (BLOCK_SIZE * TOTAL_BLOCKS) as usize])
            .unwrap();
        drop(file);

        let mut disk = ImgFileDisk::open(path).unwrap();
        let buffer = vec![0u8; (BLOCK_SIZE - 1) as usize];
        let result = disk.write_block(0, &buffer);

        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), Error::Validation("Buffer is too small to contain a block".to_string()));

        fs::remove_file(path).unwrap();
    }

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
        use crate::MyFS;

        let path = Path::new("test_format_clear.img");
        let mut file = fs::File::create(path).unwrap();
        // Write data into all blocks in the file
        file.write_all(&vec![0xFF; (BLOCK_SIZE * TOTAL_BLOCKS) as usize])
            .unwrap();
        drop(file);

        let mut disk = ImgFileDisk::open(path).unwrap();
        let mut buffer = vec![0u8; BLOCK_SIZE as usize];

        // Ensure the data exists in the file
        for block_index in 0..TOTAL_BLOCKS {
            disk.read_block(block_index, &mut buffer).unwrap();
        }
        assert_eq!(buffer, vec![0xFFu8; BLOCK_SIZE as usize]);

        // Format the disk
        MyFS::format(&mut disk).unwrap();

        // Ensure the data is cleared after formatting
        for block_index in 0..TOTAL_BLOCKS {
            disk.read_block(block_index, &mut buffer).unwrap();
        }
        assert_eq!(buffer, vec![0u8; BLOCK_SIZE as usize]);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_format_writes_superblock() {
        use crate::MyFS;

        let path = Path::new("test_format_superblock.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();

        let mut buffer = vec![0u8; BLOCK_SIZE as usize];
        disk.read_block(0, &mut buffer).unwrap();

        let superblock = Superblock::try_from_bytes(&buffer).unwrap();
        assert_eq!(superblock.magic_number, MAGIC_NUMBER);
        assert_eq!(superblock.version, 1);
        assert_eq!(superblock.block_size, BLOCK_SIZE);
        assert_eq!(superblock.total_blocks, TOTAL_BLOCKS);
        assert_eq!(superblock.inode_count, INODE_COUNT);
        assert_eq!(superblock.inode_size, INODE_SIZE);
        assert_eq!(superblock.inode_bitmap_start, 1);
        assert_eq!(superblock.data_bitmap_start, 2);
        assert_eq!(superblock.inode_table_start, 3);
        assert_eq!(superblock.data_block_start, 4);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_format_writes_inode_bitmap() {
        use crate::MyFS;

        let path = Path::new("test_format_inode_bitmap.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();

        let mut buffer = vec![0u8; BLOCK_SIZE as usize];
        disk.read_block(1, &mut buffer).unwrap();

        let inode_bitmap = Bitmap(buffer);
        assert!(inode_bitmap.is_bit_set(0));
        assert!(!inode_bitmap.is_bit_set(1));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_format_writes_data_bitmap() {
        use crate::MyFS;

        let path = Path::new("test_format_data_bitmap.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();

        let mut buffer = vec![0u8; BLOCK_SIZE as usize];
        disk.read_block(2, &mut buffer).unwrap();

        let data_bitmap = Bitmap(buffer);
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
        use crate::{MyFS, Inode, InodeKind};

        let path = Path::new("test_format_root_inode.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        MyFS::format(&mut disk).unwrap();

        let mut buffer = vec![0u8; BLOCK_SIZE as usize];
        disk.read_block(3, &mut buffer).unwrap();

        let root_inode = Inode::try_from_bytes(&buffer[0..INODE_SIZE as usize]).unwrap();
        assert_eq!(root_inode.kind, InodeKind::Directory);
        assert_eq!(root_inode.size, 0);
        assert_eq!(root_inode.direct_block, 4);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn myfs_format_succeeds() {
        use crate::MyFS;

        let path = Path::new("test_format_success.img");
        fs::File::create(path).unwrap();

        let mut disk = ImgFileDisk::open(path).unwrap();
        let result = MyFS::format(&mut disk);

        assert!(result.is_ok());

        fs::remove_file(path).unwrap();
    }
}
