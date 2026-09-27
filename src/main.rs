use clap::Parser;
use std::io::{self, Write};
use object::elf;
use object::read::elf::{ElfFile64, ProgramHeader, SectionHeader};
use object::{Endianness, Object, ObjectSection};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Binary to run
    binary: String
}

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FatBinPtr {
    pub magic: u32,
    pub version: u32,
    pub fatbin_data: u64,
    pub filename_or_bin: u64
}

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FatBinHdr {
    pub magic: u32,
    pub version: u16,
    pub header_size: u16,
    pub fatbin_size: u64
}

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FatBinInfo {
    pub kind: u16,
    pub version: u16,
    pub header_size: u32,
    pub padded_payload_size: u64,
    pub payload_size: u32,
    pub ptxas_options_offset: u32,
    pub code_version_minor: u16,
    pub code_version_major: u16,
    pub arch: u32,
    pub identifier_offset: u32,
    pub field_24: u32,
    pub bin_info: u64,
    pub field_30: u64,
    pub uncompressed_size: u64
}

pub struct FatBinEntry {
    pub fatbin_info: FatBinInfo,
    pub payload_offset: usize
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct DataLoc {
    offset: usize,
    size: usize
}

pub struct FatBin {
    pub ptr: FatBinPtr,
    pub hdr: FatBinHdr,
    pub entries: Vec<FatBinEntry>
}

fn read_le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn read_le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn read_le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..(o + 8)].try_into().unwrap())
}

fn write_le16(b: &mut [u8], o: usize, val: u16) -> () {
    b[o..(o + 2)].copy_from_slice(&val.to_le_bytes());
}

fn write_le32(b: &mut [u8], o: usize, val: u32) -> () {
    b[o..(o + 4)].copy_from_slice(&val.to_le_bytes());
}

fn separator() {
    println!("-------------------------");
}

fn get_section(elf: &ElfFile64::<Endianness>, name: &str) -> (usize, usize) {
    let fatbin_hdr = elf
        .section_by_name(name)
        .unwrap()
        .elf_section_header();
    ( fatbin_hdr.sh_addr(elf.endian()) as usize,
      fatbin_hdr.sh_size(elf.endian()) as usize )
}

fn get_section_data(elf: &ElfFile64::<Endianness>, name: &str, data: &[u8]) -> Vec<u8> {
    let (sec_addr, sec_size) = get_section(&elf, name);
    data[sec_addr..sec_addr + sec_size].to_vec()
}
 
fn get_fatbin_ptrs_from_sec_data(fatbin_seg_data: &Vec<u8>) -> Vec<FatBinPtr> {
    fatbin_seg_data
        .chunks_exact(std::mem::size_of::<FatBinPtr>())
        .map(|c| *bytemuck::from_bytes(c))
        .collect::<Vec<_>>()
        .to_vec()
}

fn get_fatbin_ptrs(elf: &ElfFile64::<Endianness>, data: &[u8]) -> Vec<FatBinPtr> {
    get_fatbin_ptrs_from_sec_data(&get_section_data(elf, ".nvFatBinSegment", data))
}

fn get_fatbin_ptr_data(ptr: &FatBinPtr, data: &[u8]) -> io::Result<FatBin> {
    if ptr.magic != 0x466243b1 {
        return Err(io::Error::other(format!("Invalid magic in FatBinPtr: {:#x}",
                    ptr.magic)));
    }

    let data_start = ptr.fatbin_data as usize;

    let magic = read_le32(&data, data_start);
    if magic != 0xba55ed50 {
        return Err(io::Error::other(format!("Invalid magic in FatBinHdr: {:#x}", magic)));
    }
 
    let data_end = data_start + std::mem::size_of::<FatBinHdr>();
    let data_slice = &data[data_start..data_end];
    let hdr: FatBinHdr = *bytemuck::from_bytes(data_slice);

    let mut curr_off = data_start + hdr.header_size as usize;
    let end_off = data_start + hdr.fatbin_size as usize;
    let mut entries = Vec::<FatBinEntry>::new();

    while curr_off <= end_off {
        let fatbin_info_end = curr_off + std::mem::size_of::<FatBinInfo>();
        let fatbin_info_data = &data[curr_off..fatbin_info_end];
        let fatbin_info: FatBinInfo = *bytemuck::from_bytes(fatbin_info_data);
        let payload_offset = curr_off + fatbin_info.header_size as usize;

        entries.push(FatBinEntry { fatbin_info, payload_offset });
        curr_off += fatbin_info.header_size as usize;
        curr_off += fatbin_info.padded_payload_size as usize;
    }

    Ok(FatBin { ptr: *ptr, hdr, entries })
}

fn print_fatbin_hdrs(fatbin_info: &Vec<FatBin>) {
    for (i, FatBin{ptr, hdr, entries}) in fatbin_info.iter().enumerate() {
        separator();
        println!("{:8}: version: {:#x}", i, hdr.version);
        println!("{:10}header_size: {}", "", hdr.header_size);
        println!("{:10}fatbin_size: {}", "", hdr.fatbin_size);
        println!("{:10}fatbin_data: {:#x}", "", ptr.fatbin_data);
    }
    separator();
}

fn select_fatbin(fatbin_info: &Vec<FatBin>) -> i16 {
    let mut buf = String::new();

    print_fatbin_hdrs(&fatbin_info);
    print!("Select FatBin (0-{}): ", fatbin_info.len() - 1);
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut buf).unwrap();
    separator();

    if let Ok(choice) = buf.trim().parse() {
        if (choice < 0) || (choice as usize >= fatbin_info.len()) {
            println!("Invalid FatBin selection: {}", choice);
            separator();
            return -1;
        }
        return choice;
    }

    println!("Invalid input: {}", buf.trim());
    separator();

    -1
}

fn print_fatbin_entries(fatbin: &FatBin) {
    let FatBin{ ptr, hdr, entries } = fatbin;
    separator();
    for (i, entry) in entries.iter().enumerate() {
        println!("{:8}: {:#08x}", i, entry.payload_offset);
    }
    separator();
}

fn select_fatbin_entry(fatbin: &FatBin) -> i16 {
    let mut buf = String::new();

    print_fatbin_entries(&fatbin);
    print!("Select FatBin entry (0-{}): ", fatbin.entries.len() - 1);
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut buf).unwrap();
    separator();

    if let Ok(choice) = buf.trim().parse() {
        if (choice < 0) || (choice as usize >= fatbin.entries.len()) {
            println!("Invalid FatBin selection: {}", choice);
            separator();
            return -1;
        }
        return choice;
    }

    println!("Invalid input: {}", buf.trim());
    separator();

    -1
}

fn select_entry_section(entry: &FatBinEntry, data: &[u8]) -> Option<String> {
    let mut buf = String::new();

    let sections = list_entry_sections(entry, data)?;
    if sections.is_empty() {
        return None;
    }

    print_entry_sections(&sections);

    print!("Select FatBin entry section (0-{}): ", sections.len() - 1);
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut buf).unwrap();
    separator();

    if let Ok(choice) = buf.trim().parse::<usize>() {
        if choice >= sections.len() {
            println!("Invalid FatBin selection: {}", choice);
            separator();
            return None
        }

        return Some(sections[choice].clone());
    }

    println!("Invalid input: {}", buf.trim());
    separator();

    None
}

fn get_entry_elf<'a>(entry: &'a FatBinEntry, data: &'a [u8]) -> Result<ElfFile64::<'a, Endianness>, object::Error> {
    let FatBinEntry{ fatbin_info, payload_offset } = entry;
    let payload = &data[*payload_offset..fatbin_info.padded_payload_size as usize + *payload_offset];
    ElfFile64::<Endianness>::parse(payload)
}

fn dump_entry(entry: &FatBinEntry, data: &[u8]) {
    let FatBinEntry{ fatbin_info, payload_offset } = entry;
    let payload = &data[*payload_offset..fatbin_info.padded_payload_size as usize + *payload_offset];

    separator();
    for (i, w64) in payload.chunks_exact(8).enumerate() {
        println!("{:08x}: {:016x}", *payload_offset + i * 8, read_le64(w64, 0x0));
    }
    separator();
}

fn list_entry_sections(entry: &FatBinEntry, data: &[u8]) -> Option<Vec<String>> {
    let mut res = Vec::<String>::new();
    if let Ok(elf) = get_entry_elf(entry, data) {
        for (i, section) in elf.sections().enumerate() {
            res.push(String::from(section.name().unwrap_or("?")))
        }
    } else {
        println!("Payload is not an ELF file.");
        return None;
    }
    Some(res)
}

fn print_entry_sections(sections: &Vec<String>) {
    separator();
    sections.iter().enumerate().for_each(|(i, s)| println!("{:8} {}", i, s));
    separator();
}

fn dump_entry_section(entry: &FatBinEntry, data: &[u8], section: &str) -> Option<(usize, usize)> {
    separator();
    if let Ok(elf) = get_entry_elf(entry, data) {
        if let Some(sec) = elf.section_by_name(section) {
            let (sec_start, sec_size) = sec.file_range().unwrap();
            let data_start = entry.payload_offset + sec_start as usize;
            let sec_data = &data[data_start..data_start + sec_size as usize];
            for (i, w64) in sec_data.chunks_exact(8).enumerate() {
                println!("{:08x}: {:016x}", data_start + i * 8, read_le64(w64, 0x0));
            }
            separator();
            return Some((data_start, data_start + sec_size as usize));
        }
    } else {
        println!("Payload is not an ELF file.")
    }
    separator();
    None
}

fn modify_entry_section(entry: &FatBinEntry, data: &mut [u8], section: &str) {
    let mut buf = String::new();
    let (start, end) = dump_entry_section(entry, data, section).unwrap();
    print!("Select address to modify: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut buf).unwrap();
    if let Ok(addr) = u64::from_str_radix(&buf.trim(), 16) {
        if ((addr as usize) < start) || ((addr as usize) >= end) {
            separator();
            println!("Address not in section range: {:#08x}..{:#08x}", start, end);
        } else {
            buf.clear();
            separator();
            print!("Type in new value: ");
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut buf).unwrap();
            if let Ok(new) = u64::from_str_radix(&buf.trim(), 16) {
                data[addr as usize..(addr as usize) + 8].copy_from_slice(&new.to_le_bytes());
            } else {
                separator();
                println!("Invalid input: {}", buf.trim());
            }
        }
    } else {
        separator();
        println!("Invalid input: {}", buf.trim());
    }
    separator();
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let mut data = std::fs::read(&args.binary)?;
    let elf = ElfFile64::<Endianness>::parse(&*data).unwrap();

    let fatbins: Vec<FatBin> = get_fatbin_ptrs(&elf, &data)
        .iter()
        .map(|p| get_fatbin_ptr_data(p, &data).unwrap())
        .collect::<Vec<_>>();

    let mut fatbin: i16 = -1;
    let mut entry: i16 = -1;
    let mut section: Option<String> = None;

    while true {
        let mut invalid = 0;
        let mut buf = String::new();

        println!("[ 1] Print FatBin info");
        println!("[ 2] Select FatBin");

        if fatbin != -1 {
            println!("[ 3] Print FatBin[{}] entries", fatbin);
            println!("[ 4] Select FatBin[{}] entry", fatbin);
        }

        if entry != -1 {
            println!("[ 5] Dump FatBin[{}].entry[{}]", fatbin, entry);
            println!("[ 6] Print FatBin[{}].entry[{}] sections", fatbin, entry);
            println!("[ 7] Select FatBin[{}].entry[{}] section", fatbin, entry);
        }

        if let Some(ref sec) = section {
            println!("[ 8] Dump '{}' from FatBin[{}].entry[{}]", sec, fatbin, entry);
            println!("[ 9] Modify '{}' fron FatBin[{}].entry[{}]", sec, fatbin, entry);
            println!("[10] Save changes");
        }

        println!("[ 0] Exit");
        separator();
        print!("> ");
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut buf).unwrap();

        if let Ok(choice) = buf.trim().parse() {
           match choice {
                1 => print_fatbin_hdrs(&fatbins),
                2 => {
                    fatbin = select_fatbin(&fatbins);
                    entry = -1;
                    section = None;
                },
                3 => if fatbin != -1 {
                    print_fatbin_entries(&fatbins[fatbin as usize]);
                } else {
                    invalid = 1;
                },
                4 => if fatbin != -1 {
                    entry = select_fatbin_entry(&fatbins[fatbin as usize]);
                    section = None;
                } else {
                    invalid = 1;
                },
                5 => if entry != -1 {
                    dump_entry(&fatbins[fatbin as usize].entries[entry as usize], &data);
                } else {
                    invalid = 1;
                },
                6 => if entry != -1 {
                    if let Some(sections) = list_entry_sections(&fatbins[fatbin as usize].entries[entry as usize], &data) {
                        print_entry_sections(&sections);
                    }
                } else {
                    invalid = 1;
                },
                7 => if entry != -1 {
                    section = select_entry_section(&fatbins[fatbin as usize].entries[entry as usize], &data);
                } else {
                    invalid = 1;
                },
                8 => if let Some(ref sec) = section {
                    dump_entry_section(&fatbins[fatbin as usize].entries[entry as usize], &data, sec);
                } else {
                    invalid = 1;
                },
                9 => if let Some(ref sec) = section {
                    modify_entry_section(&fatbins[fatbin as usize].entries[entry as usize], &mut data, sec);
                } else {
                    invalid = 1;
                },
                10 => {
                    std::fs::write(&args.binary, &data).unwrap();
                    separator();
                    println!("Successfully saved changes.");
                    separator();
                },
                0 => break,
                _ => {
                    invalid = 1
                }
            }

            if invalid == 1 {
                separator();
                println!("Invalid choice: {}", choice);
                separator();
            }

        } else {
            separator();
            println!("Invalid input: {}", buf.trim());
            separator();
        }
    }

    Ok(())
}
