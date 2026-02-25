#![deny(clippy::all)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use napi::bindgen_prelude::*;
use napi::Task;
use napi_derive::napi;
use rayon::prelude::*;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory,WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW, Thread32First, Thread32Next, MODULEENTRY32W, PROCESSENTRY32W, THREADENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD};
use windows::Win32::System::Memory::{VirtualProtectEx, VirtualQueryEx, VirtualAllocEx, VirtualFreeEx, MEMORY_BASIC_INFORMATION, PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE, VIRTUAL_FREE_TYPE};
use windows::Win32::System::Threading::{OpenProcess, OpenThread, SuspendThread, ResumeThread, CreateRemoteThread, WaitForSingleObject, GetExitCodeProcess, PROCESS_ACCESS_RIGHTS, PROCESS_ALL_ACCESS, PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, PROCESS_DELETE, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_READ_CONTROL, PROCESS_SET_INFORMATION, PROCESS_SET_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_SET_SESSIONID, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_WRITE_DAC, PROCESS_WRITE_OWNER, THREAD_SUSPEND_RESUME};

// SAFETY: Windows process handles are kernel objects valid process-wide,
// safe to use from any thread within the same process.
#[derive(Clone, Copy)]
struct SendHandle(HANDLE);
unsafe impl Send for SendHandle {}
unsafe impl Sync for SendHandle {}

#[napi]
pub enum ProcessAccessRights {
    AllAccess,
    CreateProcess,
    CreateThread,
    Delete,
    DupHandle,
    QueryInformation,
    QueryLimitedInformation,
    ReadControl,
    SetInformation,
    SetLimitedInformation,
    SetQuota,
    SetSessionId,
    Synchronize,
    Terminate,
    VmOperation,
    VmRead,
    VmWrite,
    WriteDac,
    WriteOwner,
}

impl From<ProcessAccessRights> for PROCESS_ACCESS_RIGHTS {
    fn from(process_access_rights: ProcessAccessRights) -> Self {
        match process_access_rights {
            ProcessAccessRights::AllAccess => PROCESS_ALL_ACCESS,
            ProcessAccessRights::CreateProcess => PROCESS_CREATE_PROCESS,
            ProcessAccessRights::CreateThread => PROCESS_CREATE_THREAD,
            ProcessAccessRights::Delete => PROCESS_DELETE,
            ProcessAccessRights::DupHandle => PROCESS_DUP_HANDLE,
            ProcessAccessRights::QueryInformation => PROCESS_QUERY_INFORMATION,
            ProcessAccessRights::QueryLimitedInformation => PROCESS_QUERY_LIMITED_INFORMATION,
            ProcessAccessRights::ReadControl => PROCESS_READ_CONTROL,
            ProcessAccessRights::SetInformation => PROCESS_SET_INFORMATION,
            ProcessAccessRights::SetLimitedInformation => PROCESS_SET_LIMITED_INFORMATION,
            ProcessAccessRights::SetQuota => PROCESS_SET_QUOTA,
            ProcessAccessRights::SetSessionId => PROCESS_SET_SESSIONID,
            ProcessAccessRights::Synchronize => PROCESS_SYNCHRONIZE,
            ProcessAccessRights::Terminate => PROCESS_TERMINATE,
            ProcessAccessRights::VmOperation => PROCESS_VM_OPERATION,
            ProcessAccessRights::VmRead => PROCESS_VM_READ,
            ProcessAccessRights::VmWrite => PROCESS_VM_WRITE,
            ProcessAccessRights::WriteDac => PROCESS_WRITE_DAC,
            ProcessAccessRights::WriteOwner => PROCESS_WRITE_OWNER,
        }
    }
}

fn parse_ida_pattern(pattern_str: &str) -> (Vec<u8>, Vec<u8>) {
    let mut pattern = Vec::new();
    let mut mask = Vec::new();
    for token in pattern_str.split_whitespace() {
        if token == "?" || token == "??" {
            pattern.push(0x00);
            mask.push(b'?');
        } else {
            pattern.push(u8::from_str_radix(token, 16).unwrap_or(0));
            mask.push(b'x');
        }
    }
    (pattern, mask)
}

#[napi]
pub enum PageProtection {
    NoAccess = 0x01,
    ReadOnly = 0x02,
    ReadWrite = 0x04,
    WriteCopy = 0x08,
    Execute = 0x10,
    ExecuteRead = 0x20,
    ExecuteReadWrite = 0x40,
    ExecuteWriteCopy = 0x80,
    Guard = 0x100,
    NoCache = 0x200,
    WriteCombine = 0x400,
}

#[napi]
pub enum MemoryAllocationType {
    Commit = 0x00001000,
    Reserve = 0x00002000,
    CommitReserve = 0x00003000,
    Decommit = 0x00004000,
    Release = 0x00008000,
    Reset = 0x00080000,
    TopDown = 0x00100000,
    LargePages = 0x20000000,
}

#[napi(object)]
#[derive(Debug)]
pub struct Process {
    pub pid: u32,
    pub name: String,
}

#[napi]
pub fn enumerate_processes() -> Result<Vec<Process>> {
    let mut processes = Vec::new();

    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(handle) => handle,
        Err(err) => return Err(Error::new(
            Status::GenericFailure,
            format!("Failed to create process snapshot: {:?}", err)
        )),
    };

    let mut process_entry = PROCESSENTRY32W::default();
    process_entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    if let Err(err) = unsafe { Process32FirstW(snapshot, &mut process_entry) } {
        unsafe { CloseHandle(snapshot) }.ok();
        return Err(Error::new(Status::GenericFailure, format!("Failed to get first process: {:?}", err)));
    }

    loop {
        let len = process_entry.szExeFile.iter()
            .position(|&c| c == 0)
            .unwrap_or(process_entry.szExeFile.len());

        let curr = OsString::from_wide(&process_entry.szExeFile[..len])
            .into_string()
            .unwrap_or_default();

        processes.push(Process {
            pid: process_entry.th32ProcessID,
            name: curr,
        });

        if let Err(_) = unsafe { Process32NextW(snapshot, &mut process_entry) } {
            break;
        }
    }

    if let Err(err) = unsafe { CloseHandle(snapshot) } {
        return Err(Error::new(Status::GenericFailure, format!("Failed to close snapshot handle: {:?}", err)));
    }

    Ok(processes)
}

#[napi(object)]
#[derive(Debug)]
pub struct Module {
    pub name: String,
    pub path: String,
    pub base_address: BigInt,
    pub base_size: u32,
}

#[napi]
pub fn enumerate_modules(pid: u32) -> Result<Vec<Module>> {
    let mut modules = Vec::new();

    let process_handle = match unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
    } {
        Ok(handle) => handle,
        Err(err) => return Err(Error::new(
            Status::GenericFailure,
            format!("Failed to open process {}: {:?}", pid, err)
        )),
    };

    let snapshot = match unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    } {
        Ok(handle) => handle,
        Err(err) => {
            unsafe { CloseHandle(process_handle) }.ok();
            return Err(Error::new(
                Status::GenericFailure,
                format!("Failed to create module snapshot for PID {}: {:?}", pid, err)
            ));
        }
    };

    let mut module_entry = MODULEENTRY32W::default();
    module_entry.dwSize = size_of::<MODULEENTRY32W>() as u32;

    if let Err(err) = unsafe { Module32FirstW(snapshot, &mut module_entry) } {
        unsafe { CloseHandle(snapshot) }.ok();
        unsafe { CloseHandle(process_handle) }.ok();
        return Err(Error::new(
            Status::GenericFailure,
            format!("Failed to get first module: {:?}", err)
        ));
    }

    loop {
        let name_len = module_entry.szModule.iter()
            .position(|&c| c == 0)
            .unwrap_or(module_entry.szModule.len());
        let name = OsString::from_wide(&module_entry.szModule[..name_len])
            .into_string()
            .unwrap_or_default();

        let path_len = module_entry.szExePath.iter()
            .position(|&c| c == 0)
            .unwrap_or(module_entry.szExePath.len());
        let path = OsString::from_wide(&module_entry.szExePath[..path_len])
            .into_string()
            .unwrap_or_default();

        modules.push(Module {
            base_address: BigInt::from(module_entry.modBaseAddr as u64),
            base_size: module_entry.modBaseSize,
            name,
            path,
        });

        if let Err(_) = unsafe { Module32NextW(snapshot, &mut module_entry) } {
            break;
        }
    }

    unsafe { CloseHandle(snapshot) }.ok();
    unsafe { CloseHandle(process_handle) }.ok();

    Ok(modules)
}

#[napi]
pub struct RawValue {
    buffer: Buffer,
}

#[napi]
impl RawValue {
    #[napi(constructor)]
    pub fn new(buffer: Buffer) -> Self {
        Self { buffer }
    }

    #[napi(factory)]
    pub fn from_buffer(buffer: Buffer) -> Self {
        Self { buffer }
    }

    #[napi(factory)]
    pub fn from_u8(value: u8) -> Self {
        Self { buffer: Buffer::from(vec![value]) }
    }

    #[napi(factory)]
    pub fn from_i8(value: i8) -> Self {
        Self { buffer: Buffer::from(vec![value as u8]) }
    }

    #[napi(factory)]
    pub fn from_i16(value: i16) -> Self {
        Self { buffer: Buffer::from(value.to_le_bytes().to_vec()) }
    }

    #[napi(factory)]
    pub fn from_u16(value: u16) -> Self {
        Self { buffer: Buffer::from(value.to_le_bytes().to_vec()) }
    }

    #[napi(factory)]
    pub fn from_i32(value: i32) -> Self {
        Self { buffer: Buffer::from(value.to_le_bytes().to_vec()) }
    }

    #[napi(factory)]
    pub fn from_u32(value: u32) -> Self {
        Self { buffer: Buffer::from(value.to_le_bytes().to_vec()) }
    }

    #[napi(factory)]
    pub fn from_i64(value: i64) -> Self {
        Self { buffer: Buffer::from(value.to_le_bytes().to_vec()) }
    }

    #[napi(factory)]
    pub fn from_u64(value: BigInt) -> Self {
        let num = value.get_u64().1;
        Self { buffer: Buffer::from(num.to_le_bytes().to_vec()) }
    }

    #[napi(factory)]
    pub fn from_f32(value: f64) -> Self {
        Self { buffer: Buffer::from((value as f32).to_le_bytes().to_vec()) }
    }

    #[napi(factory)]
    pub fn from_f64(value: f64) -> Self {
        Self { buffer: Buffer::from(value.to_le_bytes().to_vec()) }
    }

    #[napi(factory)]
    pub fn from_usize(value: BigInt) -> Self {
        let num = value.get_u64().1;
        Self { buffer: Buffer::from(num.to_le_bytes().to_vec()) }
    }

    #[napi(factory)]
    pub fn from_isize(value: BigInt) -> Self {
        let num = value.get_i64().0;
        Self { buffer: Buffer::from(num.to_le_bytes().to_vec()) }
    }

    #[napi(factory)]
    pub fn from_string(value: String, encoding: Option<String>) -> Result<Self> {
        let encoding = encoding.unwrap_or_else(|| "utf8".to_string());

        match encoding.as_str() {
            "utf8" => {
                let mut bytes = value.into_bytes();
                bytes.push(0);
                Ok(Self { buffer: Buffer::from(bytes) })
            }
            "utf16" | "utf16le" => {
                let mut u16_vec: Vec<u16> = value.encode_utf16().collect();
                u16_vec.push(0);
                let bytes: Vec<u8> = u16_vec.iter()
                    .flat_map(|&c| c.to_le_bytes())
                    .collect();
                Ok(Self { buffer: Buffer::from(bytes) })
            }
            _ => Err(Error::new(Status::InvalidArg, format!("Unsupported encoding: {}", encoding)))
        }
    }

    #[napi]
    pub fn to_u8(&self) -> Result<u8> {
        if self.buffer.len() < 1 {
            return Err(Error::new(Status::InvalidArg, "Buffer too small for u8"));
        }
        Ok(self.buffer[0])
    }

    #[napi]
    pub fn to_i8(&self) -> Result<i8> {
        if self.buffer.len() < 1 {
            return Err(Error::new(Status::InvalidArg, "Buffer too small for i8"));
        }
        Ok(self.buffer[0] as i8)
    }

    #[napi]
    pub fn to_i16(&self) -> Result<i16> {
        if self.buffer.len() < 2 {
            return Err(Error::new(Status::InvalidArg, "Buffer too small for i16"));
        }
        Ok(i16::from_le_bytes([self.buffer[0], self.buffer[1]]))
    }

    #[napi]
    pub fn to_u16(&self) -> Result<u16> {
        if self.buffer.len() < 2 {
            return Err(Error::new(Status::InvalidArg, "Buffer too small for u16"));
        }
        Ok(u16::from_le_bytes([self.buffer[0], self.buffer[1]]))
    }

    #[napi]
    pub fn to_i32(&self) -> Result<i32> {
        if self.buffer.len() < 4 {
            return Err(Error::new(Status::InvalidArg, "Buffer too small for i32"));
        }
        let bytes: [u8; 4] = self.buffer[0..4].try_into()
            .map_err(|_| Error::new(Status::InvalidArg, "Failed to convert to i32"))?;
        Ok(i32::from_le_bytes(bytes))
    }

    #[napi]
    pub fn to_u32(&self) -> Result<u32> {
        if self.buffer.len() < 4 {
            return Err(Error::new(Status::InvalidArg, "Buffer too small for u32"));
        }
        let bytes: [u8; 4] = self.buffer[0..4].try_into()
            .map_err(|_| Error::new(Status::InvalidArg, "Failed to convert to u32"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    #[napi]
    pub fn to_i64(&self) -> Result<i64> {
        if self.buffer.len() < 8 {
            return Err(Error::new(Status::InvalidArg, "Buffer too small for i64"));
        }
        let bytes: [u8; 8] = self.buffer[0..8].try_into()
            .map_err(|_| Error::new(Status::InvalidArg, "Failed to convert to i64"))?;
        Ok(i64::from_le_bytes(bytes))
    }

    #[napi]
    pub fn to_u64(&self) -> Result<BigInt> {
        if self.buffer.len() < 8 {
            return Err(Error::new(Status::InvalidArg, "Buffer too small for u64"));
        }
        let bytes: [u8; 8] = self.buffer[0..8].try_into()
            .map_err(|_| Error::new(Status::InvalidArg, "Failed to convert to u64"))?;
        Ok(BigInt::from(u64::from_le_bytes(bytes)))
    }

    #[napi]
    pub fn to_f32(&self) -> Result<f64> {
        if self.buffer.len() < 4 {
            return Err(Error::new(Status::InvalidArg, "Buffer too small for f32"));
        }
        let bytes: [u8; 4] = self.buffer[0..4].try_into()
            .map_err(|_| Error::new(Status::InvalidArg, "Failed to convert to f32"))?;
        Ok(f32::from_le_bytes(bytes) as f64)
    }

    #[napi]
    pub fn to_f64(&self) -> Result<f64> {
        if self.buffer.len() < 8 {
            return Err(Error::new(Status::InvalidArg, "Buffer too small for f64"));
        }
        let bytes: [u8; 8] = self.buffer[0..8].try_into()
            .map_err(|_| Error::new(Status::InvalidArg, "Failed to convert to f64"))?;
        Ok(f64::from_le_bytes(bytes))
    }

    #[napi]
    pub fn to_usize(&self) -> Result<BigInt> {
        if self.buffer.len() < 8 {
            return Err(Error::new(Status::InvalidArg, "Buffer too small for usize"));
        }
        let bytes: [u8; 8] = self.buffer[0..8].try_into()
            .map_err(|_| Error::new(Status::InvalidArg, "Failed to convert to usize"))?;
        Ok(BigInt::from(u64::from_le_bytes(bytes)))
    }

    #[napi]
    pub fn to_isize(&self) -> Result<BigInt> {
        if self.buffer.len() < 8 {
            return Err(Error::new(Status::InvalidArg, "Buffer too small for isize"));
        }
        let bytes: [u8; 8] = self.buffer[0..8].try_into()
            .map_err(|_| Error::new(Status::InvalidArg, "Failed to convert to isize"))?;
        Ok(BigInt::from(i64::from_le_bytes(bytes)))
    }

    #[napi]
    pub fn to_string(&self, encoding: Option<String>) -> Result<String> {
        let encoding = encoding.unwrap_or_else(|| "utf8".to_string());

        match encoding.as_str() {
            "utf8" => {
                let end = self.buffer.iter().position(|&b| b == 0).unwrap_or(self.buffer.len());
                String::from_utf8(self.buffer[..end].to_vec())
                    .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid UTF-8: {}", e)))
            }
            "utf16" | "utf16le" => {
                if self.buffer.len() % 2 != 0 {
                    return Err(Error::new(Status::InvalidArg, "Buffer length must be even for UTF-16"));
                }
                let u16_vec: Vec<u16> = self.buffer
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .take_while(|&c| c != 0)
                    .collect();

                String::from_utf16(&u16_vec)
                    .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid UTF-16: {}", e)))
            }
            _ => Err(Error::new(Status::InvalidArg, format!("Unsupported encoding: {}", encoding)))
        }
    }
}

#[napi(object)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: BigInt,
    pub virtual_size: u32,
}

#[napi(object)]
pub struct ReadRequest {
    pub address: BigInt,
    pub size: u32,
}

#[napi(object)]
pub struct MemoryRegionInfo {
    pub base_address: BigInt,
    pub allocation_base: BigInt,
    pub allocation_protect: u32,
    pub region_size: BigInt,
    pub state: u32,
    pub protect: u32,
    pub memory_type: u32,
}

#[napi]
pub struct OpenedProcess {
    handle: HANDLE,
    pid: u32,
    closed: bool,
}

fn read_raw_handle(handle: SendHandle, address: usize, size: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0;

    match unsafe {
        ReadProcessMemory(
            handle.0,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        )
    } {
        Ok(_) => {
            buffer.truncate(bytes_read);
            Ok(buffer)
        }
        Err(err) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to read memory at address 0x{:X}: {:?}", address, err)
        )),
    }
}

fn scan_region_raw(handle: SendHandle, start_address: usize, total_size: usize, pattern_bytes: &[u8], mask_bytes: &[u8]) -> Result<Vec<usize>> {
    let pattern_len = pattern_bytes.len();
    let mut matches = Vec::new();
    let chunk_size: usize = 1024 * 1024;
    let overlap = pattern_len.saturating_sub(1);
    let mut offset: usize = 0;

    while offset < total_size {
        let read_size = std::cmp::min(chunk_size + overlap, total_size - offset);
        let chunk = match read_raw_handle(handle, start_address + offset, read_size) {
            Ok(c) => c,
            Err(_) => break,
        };

        if chunk.len() < pattern_len {
            break;
        }

        let owned_size = if offset + chunk_size < total_size { chunk_size } else { chunk.len() };
        let search_end = if owned_size >= pattern_len {
            owned_size - pattern_len + 1
        } else {
            0
        };

        for i in 0..search_end {
            let mut found = true;
            for j in 0..pattern_len {
                if mask_bytes[j] == b'x' && chunk[i + j] != pattern_bytes[j] {
                    found = false;
                    break;
                }
            }
            if found {
                matches.push(start_address + offset + i);
            }
        }

        offset += chunk_size;
    }

    Ok(matches)
}

struct ScanRegion {
    base: usize,
    size: usize,
}

fn collect_scan_regions(handle: HANDLE) -> Vec<ScanRegion> {
    let mut regions = Vec::new();
    let mut address: usize = 0;

    loop {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        let result = unsafe {
            VirtualQueryEx(
                handle,
                Some(address as *const _),
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break;
        }

        let region_base = info.BaseAddress as usize;
        let region_size = info.RegionSize;

        if info.State.0 == 0x1000
            && (info.Protect.0 & 0x01) == 0
            && (info.Protect.0 & 0x100) == 0
        {
            regions.push(ScanRegion {
                base: region_base,
                size: region_size,
            });
        }

        address = region_base + region_size;
        if address <= region_base {
            break;
        }
    }

    regions
}

pub struct ScanAllTask {
    handle: SendHandle,
    pattern: Vec<u8>,
    mask: Vec<u8>,
}

impl Task for ScanAllTask {
    type Output = Vec<u64>;
    type JsValue = Vec<BigInt>;

    fn compute(&mut self) -> Result<Self::Output> {
        if self.pattern.is_empty() {
            return Ok(vec![]);
        }

        let handle = self.handle;
        let pattern = &self.pattern;
        let mask = &self.mask;
        let regions = collect_scan_regions(handle.0);

        let all_matches: Vec<usize> = regions
            .par_iter()
            .flat_map(|region| {
                scan_region_raw(handle, region.base, region.size, pattern, mask)
                    .unwrap_or_default()
            })
            .collect();

        Ok(all_matches.into_iter().map(|a| a as u64).collect())
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into_iter().map(BigInt::from).collect())
    }
}

impl OpenedProcess {
    fn ensure_open(&self) -> Result<()> {
        if self.closed {
            return Err(Error::new(Status::GenericFailure, "Process handle has been closed"));
        }
        Ok(())
    }

    fn read_raw(&self, address: usize, size: usize) -> Result<Vec<u8>> {
        self.ensure_open()?;
        read_raw_handle(SendHandle(self.handle), address, size)
    }

    fn write_raw(&self, address: usize, data: &[u8]) -> Result<usize> {
        self.ensure_open()?;
        let mut bytes_written = 0;
        match unsafe {
            WriteProcessMemory(
                self.handle,
                address as *mut _,
                data.as_ptr() as *const _,
                data.len(),
                Some(&mut bytes_written),
            )
        } {
            Ok(_) => Ok(bytes_written),
            Err(err) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to write memory at address 0x{:X}: {:?}", address, err)
            )),
        }
    }

    fn resolve_pointer_chain(&self, base: usize, offsets: &[BigInt]) -> Result<usize> {
        let mut address = base;

        for offset in offsets {
            let bytes = self.read_raw(address, 8)?;
            if bytes.len() != 8 {
                return Err(Error::new(
                    Status::GenericFailure,
                    format!("Failed to read full pointer at address 0x{:X}", address)
                ));
            }
            address = u64::from_le_bytes(bytes.try_into().unwrap()) as usize + (offset.get_u64().1 as usize);
        }

        Ok(address)
    }

    fn scan_region(&self, start_address: usize, total_size: usize, pattern_bytes: &[u8], mask_bytes: &[u8]) -> Result<Vec<usize>> {
        self.ensure_open()?;
        scan_region_raw(SendHandle(self.handle), start_address, total_size, pattern_bytes, mask_bytes)
    }
}

#[napi]
impl OpenedProcess {
    #[napi(ts_return_type = "RawValue")]
    pub fn read_memory(&self, address: BigInt, size: u32) -> Result<RawValue> {
        let address = address.get_u64().1 as usize;
        let buffer = self.read_raw(address, size as usize)?;
        Ok(RawValue { buffer: Buffer::from(buffer) })
    }

    #[napi(ts_return_type = "RawValue")]
    pub fn read_pointer_chain(&self, base_address: BigInt, offsets: Vec<BigInt>, size: u32) -> Result<RawValue> {
        let base = base_address.get_u64().1 as usize;
        let address = self.resolve_pointer_chain(base, &offsets)?;
        let buffer = self.read_raw(address, size as usize)?;
        Ok(RawValue { buffer: Buffer::from(buffer) })
    }

    #[napi(ts_args_type = "address: bigint, value: RawValue")]
    pub fn write_memory(&self, address: BigInt, value: &RawValue) -> Result<u32> {
        self.ensure_open()?;
        let address = address.get_u64().1 as usize;
        let size = value.buffer.len();
        let mut bytes_written = 0;

        match unsafe {
            WriteProcessMemory(
                self.handle,
                address as *mut _,
                value.buffer.as_ptr() as *const _,
                size,
                Some(&mut bytes_written),
            )
        } {
            Ok(_) => Ok(bytes_written as u32),
            Err(err) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to write memory at address 0x{:X}: {:?}", address, err)
            )),
        }
    }

    #[napi(ts_args_type = "baseAddress: bigint, offsets: Array<bigint>, value: RawValue")]
    pub fn write_pointer_chain(&self, base_address: BigInt, offsets: Vec<BigInt>, value: &RawValue) -> Result<u32> {
        self.ensure_open()?;
        let base = base_address.get_u64().1 as usize;
        let address = self.resolve_pointer_chain(base, &offsets)?;
        let size = value.buffer.len();
        let mut bytes_written = 0;

        match unsafe {
            WriteProcessMemory(
                self.handle,
                address as *mut _,
                value.buffer.as_ptr() as *const _,
                size,
                Some(&mut bytes_written),
            )
        } {
            Ok(_) => Ok(bytes_written as u32),
            Err(err) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to write memory at address 0x{:X}: {:?}", address, err)
            )),
        }
    }

    #[napi]
    pub fn read_buffer(&self, address: BigInt, size: u32) -> Result<Buffer> {
        let address = address.get_u64().1 as usize;
        let buffer = self.read_raw(address, size as usize)?;
        Ok(Buffer::from(buffer))
    }

    #[napi]
    pub fn read_u8(&self, address: BigInt) -> Result<u8> {
        let address = address.get_u64().1 as usize;
        let bytes = self.read_raw(address, 1)?;
        if bytes.len() < 1 {
            return Err(Error::new(Status::GenericFailure, format!("Failed to read 1 byte at address 0x{:X}", address)));
        }
        Ok(bytes[0])
    }

    #[napi]
    pub fn read_i8(&self, address: BigInt) -> Result<i8> {
        let address = address.get_u64().1 as usize;
        let bytes = self.read_raw(address, 1)?;
        if bytes.len() < 1 {
            return Err(Error::new(Status::GenericFailure, format!("Failed to read 1 byte at address 0x{:X}", address)));
        }
        Ok(bytes[0] as i8)
    }

    #[napi]
    pub fn read_u16(&self, address: BigInt) -> Result<u16> {
        let address = address.get_u64().1 as usize;
        let bytes = self.read_raw(address, 2)?;
        if bytes.len() < 2 {
            return Err(Error::new(Status::GenericFailure, format!("Failed to read 2 bytes at address 0x{:X}", address)));
        }
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    #[napi]
    pub fn read_i16(&self, address: BigInt) -> Result<i16> {
        let address = address.get_u64().1 as usize;
        let bytes = self.read_raw(address, 2)?;
        if bytes.len() < 2 {
            return Err(Error::new(Status::GenericFailure, format!("Failed to read 2 bytes at address 0x{:X}", address)));
        }
        Ok(i16::from_le_bytes([bytes[0], bytes[1]]))
    }

    #[napi]
    pub fn read_u32(&self, address: BigInt) -> Result<u32> {
        let address = address.get_u64().1 as usize;
        let bytes = self.read_raw(address, 4)?;
        if bytes.len() < 4 {
            return Err(Error::new(Status::GenericFailure, format!("Failed to read 4 bytes at address 0x{:X}", address)));
        }
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[napi]
    pub fn read_i32(&self, address: BigInt) -> Result<i32> {
        let address = address.get_u64().1 as usize;
        let bytes = self.read_raw(address, 4)?;
        if bytes.len() < 4 {
            return Err(Error::new(Status::GenericFailure, format!("Failed to read 4 bytes at address 0x{:X}", address)));
        }
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[napi]
    pub fn read_u64(&self, address: BigInt) -> Result<BigInt> {
        let address = address.get_u64().1 as usize;
        let bytes = self.read_raw(address, 8)?;
        if bytes.len() < 8 {
            return Err(Error::new(Status::GenericFailure, format!("Failed to read 8 bytes at address 0x{:X}", address)));
        }
        let arr: [u8; 8] = bytes.try_into().unwrap();
        Ok(BigInt::from(u64::from_le_bytes(arr)))
    }

    #[napi]
    pub fn read_i64(&self, address: BigInt) -> Result<BigInt> {
        let address = address.get_u64().1 as usize;
        let bytes = self.read_raw(address, 8)?;
        if bytes.len() < 8 {
            return Err(Error::new(Status::GenericFailure, format!("Failed to read 8 bytes at address 0x{:X}", address)));
        }
        let arr: [u8; 8] = bytes.try_into().unwrap();
        Ok(BigInt::from(i64::from_le_bytes(arr)))
    }

    #[napi]
    pub fn read_f32(&self, address: BigInt) -> Result<f64> {
        let address = address.get_u64().1 as usize;
        let bytes = self.read_raw(address, 4)?;
        if bytes.len() < 4 {
            return Err(Error::new(Status::GenericFailure, format!("Failed to read 4 bytes at address 0x{:X}", address)));
        }
        Ok(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64)
    }

    #[napi]
    pub fn read_f64(&self, address: BigInt) -> Result<f64> {
        let address = address.get_u64().1 as usize;
        let bytes = self.read_raw(address, 8)?;
        if bytes.len() < 8 {
            return Err(Error::new(Status::GenericFailure, format!("Failed to read 8 bytes at address 0x{:X}", address)));
        }
        let arr: [u8; 8] = bytes.try_into().unwrap();
        Ok(f64::from_le_bytes(arr))
    }

    #[napi]
    pub fn read_pointer(&self, address: BigInt) -> Result<BigInt> {
        let address = address.get_u64().1 as usize;
        let bytes = self.read_raw(address, 8)?;
        if bytes.len() < 8 {
            return Err(Error::new(Status::GenericFailure, format!("Failed to read 8 bytes at address 0x{:X}", address)));
        }
        let arr: [u8; 8] = bytes.try_into().unwrap();
        Ok(BigInt::from(u64::from_le_bytes(arr)))
    }

    #[napi]
    pub fn read_string(&self, address: BigInt, max_length: Option<u32>, encoding: Option<String>) -> Result<String> {
        let address = address.get_u64().1 as usize;
        let max_length = max_length.unwrap_or(256) as usize;
        let encoding = encoding.unwrap_or_else(|| "utf8".to_string());

        match encoding.as_str() {
            "utf8" => {
                let bytes = self.read_raw(address, max_length)?;
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                String::from_utf8(bytes[..end].to_vec())
                    .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid UTF-8: {}", e)))
            }
            "utf16" | "utf16le" => {
                let bytes = self.read_raw(address, max_length * 2)?;
                let u16_vec: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .take_while(|&c| c != 0)
                    .collect();
                String::from_utf16(&u16_vec)
                    .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid UTF-16: {}", e)))
            }
            _ => Err(Error::new(Status::InvalidArg, format!("Unsupported encoding: {}", encoding)))
        }
    }

    #[napi]
    pub fn get_module_sections(&self, module_base: BigInt) -> Result<Vec<PeSection>> {
        let base = module_base.get_u64().1 as usize;

        let dos_header = self.read_raw(base, 64)?;
        if dos_header.len() < 64 || dos_header[0] != b'M' || dos_header[1] != b'Z' {
            return Err(Error::new(Status::InvalidArg, "Invalid DOS header (MZ signature not found)"));
        }

        let e_lfanew = u32::from_le_bytes([
            dos_header[0x3C], dos_header[0x3D], dos_header[0x3E], dos_header[0x3F]
        ]) as usize;

        let pe_header = self.read_raw(base + e_lfanew, 24)?;
        if pe_header.len() < 24
            || pe_header[0] != b'P' || pe_header[1] != b'E'
            || pe_header[2] != 0 || pe_header[3] != 0
        {
            return Err(Error::new(Status::InvalidArg, "Invalid PE signature"));
        }

        let number_of_sections = u16::from_le_bytes([pe_header[6], pe_header[7]]) as usize;
        let size_of_optional_header = u16::from_le_bytes([pe_header[20], pe_header[21]]) as usize;
        let sections_offset = base + e_lfanew + 24 + size_of_optional_header;
        let sections_data = self.read_raw(sections_offset, number_of_sections * 40)?;

        let mut sections = Vec::with_capacity(number_of_sections);
        for i in 0..number_of_sections {
            let off = i * 40;
            if off + 40 > sections_data.len() {
                break;
            }

            let name_bytes = &sections_data[off..off + 8];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

            let virtual_size = u32::from_le_bytes([
                sections_data[off + 8], sections_data[off + 9],
                sections_data[off + 10], sections_data[off + 11],
            ]);

            let virtual_address = u32::from_le_bytes([
                sections_data[off + 12], sections_data[off + 13],
                sections_data[off + 14], sections_data[off + 15],
            ]);

            sections.push(PeSection {
                name,
                virtual_address: BigInt::from(virtual_address as u64),
                virtual_size,
            });
        }

        Ok(sections)
    }

    #[napi]
    pub fn scan_pattern(&self, address: BigInt, size: u32, pattern: String) -> Result<Vec<BigInt>> {
        let start_address = address.get_u64().1 as usize;
        let (pattern_bytes, mask_bytes) = parse_ida_pattern(&pattern);

        if pattern_bytes.is_empty() {
            return Ok(vec![]);
        }

        let matches = self.scan_region(start_address, size as usize, &pattern_bytes, &mask_bytes)?;
        Ok(matches.into_iter().map(|a| BigInt::from(a as u64)).collect())
    }

    #[napi(js_name = "scanAllSync")]
    pub fn scan_all(&self, pattern: String) -> Result<Vec<BigInt>> {
        self.ensure_open()?;
        let (pattern_bytes, mask_bytes) = parse_ida_pattern(&pattern);

        if pattern_bytes.is_empty() {
            return Ok(vec![]);
        }

        let handle = SendHandle(self.handle);
        let regions = collect_scan_regions(handle.0);

        let all_matches: Vec<usize> = regions
            .par_iter()
            .flat_map(|region| {
                scan_region_raw(handle, region.base, region.size, &pattern_bytes, &mask_bytes)
                    .unwrap_or_default()
            })
            .collect();

        Ok(all_matches.into_iter().map(|a| BigInt::from(a as u64)).collect())
    }

    #[napi(js_name = "scanAll", ts_return_type = "Promise<Array<bigint>>")]
    pub fn scan_all_async(&self, pattern: String) -> Result<AsyncTask<ScanAllTask>> {
        self.ensure_open()?;
        let (pattern_bytes, mask_bytes) = parse_ida_pattern(&pattern);

        if pattern_bytes.is_empty() {
            return Ok(AsyncTask::new(ScanAllTask {
                handle: SendHandle(self.handle),
                pattern: vec![],
                mask: vec![],
            }));
        }

        Ok(AsyncTask::new(ScanAllTask {
            handle: SendHandle(self.handle),
            pattern: pattern_bytes,
            mask: mask_bytes,
        }))
    }

    // ── Typed Writes ──

    #[napi]
    pub fn write_u8(&self, address: BigInt, value: u8) -> Result<()> {
        let address = address.get_u64().1 as usize;
        self.write_raw(address, &[value])?;
        Ok(())
    }

    #[napi]
    pub fn write_i8(&self, address: BigInt, value: i8) -> Result<()> {
        let address = address.get_u64().1 as usize;
        self.write_raw(address, &[value as u8])?;
        Ok(())
    }

    #[napi]
    pub fn write_u16(&self, address: BigInt, value: u16) -> Result<()> {
        let address = address.get_u64().1 as usize;
        self.write_raw(address, &value.to_le_bytes())?;
        Ok(())
    }

    #[napi]
    pub fn write_i16(&self, address: BigInt, value: i16) -> Result<()> {
        let address = address.get_u64().1 as usize;
        self.write_raw(address, &value.to_le_bytes())?;
        Ok(())
    }

    #[napi]
    pub fn write_u32(&self, address: BigInt, value: u32) -> Result<()> {
        let address = address.get_u64().1 as usize;
        self.write_raw(address, &value.to_le_bytes())?;
        Ok(())
    }

    #[napi]
    pub fn write_i32(&self, address: BigInt, value: i32) -> Result<()> {
        let address = address.get_u64().1 as usize;
        self.write_raw(address, &value.to_le_bytes())?;
        Ok(())
    }

    #[napi]
    pub fn write_u64(&self, address: BigInt, value: BigInt) -> Result<()> {
        let address = address.get_u64().1 as usize;
        let num = value.get_u64().1;
        self.write_raw(address, &num.to_le_bytes())?;
        Ok(())
    }

    #[napi]
    pub fn write_i64(&self, address: BigInt, value: BigInt) -> Result<()> {
        let address = address.get_u64().1 as usize;
        let num = value.get_i64().0;
        self.write_raw(address, &num.to_le_bytes())?;
        Ok(())
    }

    #[napi]
    pub fn write_f32(&self, address: BigInt, value: f64) -> Result<()> {
        let address = address.get_u64().1 as usize;
        self.write_raw(address, &(value as f32).to_le_bytes())?;
        Ok(())
    }

    #[napi]
    pub fn write_f64(&self, address: BigInt, value: f64) -> Result<()> {
        let address = address.get_u64().1 as usize;
        self.write_raw(address, &value.to_le_bytes())?;
        Ok(())
    }

    #[napi]
    pub fn write_pointer(&self, address: BigInt, value: BigInt) -> Result<()> {
        let address = address.get_u64().1 as usize;
        let num = value.get_u64().1;
        self.write_raw(address, &num.to_le_bytes())?;
        Ok(())
    }

    #[napi]
    pub fn write_buffer(&self, address: BigInt, buffer: Buffer) -> Result<()> {
        let address = address.get_u64().1 as usize;
        self.write_raw(address, buffer.as_ref())?;
        Ok(())
    }

    // ── Virtual Memory ──

    #[napi]
    pub fn virtual_protect(&self, address: BigInt, size: u32, protection: u32) -> Result<u32> {
        self.ensure_open()?;
        let address = address.get_u64().1 as usize;
        let mut old_protection = PAGE_PROTECTION_FLAGS(0);

        match unsafe {
            VirtualProtectEx(
                self.handle,
                address as *const _,
                size as usize,
                PAGE_PROTECTION_FLAGS(protection),
                &mut old_protection,
            )
        } {
            Ok(_) => Ok(old_protection.0),
            Err(err) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to change memory protection at 0x{:X}: {:?}", address, err)
            )),
        }
    }

    #[napi]
    pub fn virtual_query(&self, address: BigInt) -> Result<MemoryRegionInfo> {
        self.ensure_open()?;
        let address = address.get_u64().1 as usize;
        let mut info = MEMORY_BASIC_INFORMATION::default();

        let result = unsafe {
            VirtualQueryEx(
                self.handle,
                Some(address as *const _),
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            return Err(Error::new(
                Status::GenericFailure,
                format!("Failed to query memory at 0x{:X}", address)
            ));
        }

        Ok(MemoryRegionInfo {
            base_address: BigInt::from(info.BaseAddress as u64),
            allocation_base: BigInt::from(info.AllocationBase as u64),
            allocation_protect: info.AllocationProtect.0,
            region_size: BigInt::from(info.RegionSize as u64),
            state: info.State.0,
            protect: info.Protect.0,
            memory_type: info.Type.0,
        })
    }

    #[napi]
    pub fn virtual_alloc(&self, address: BigInt, size: u32, allocation_type: u32, protection: u32) -> Result<BigInt> {
        self.ensure_open()?;
        let address = address.get_u64().1 as usize;

        let result = unsafe {
            VirtualAllocEx(
                self.handle,
                Some(address as *const _),
                size as usize,
                VIRTUAL_ALLOCATION_TYPE(allocation_type),
                PAGE_PROTECTION_FLAGS(protection),
            )
        };

        if result.is_null() {
            return Err(Error::new(
                Status::GenericFailure,
                format!("Failed to allocate memory at 0x{:X}", address)
            ));
        }

        Ok(BigInt::from(result as u64))
    }

    #[napi]
    pub fn virtual_free(&self, address: BigInt, size: u32, free_type: u32) -> Result<()> {
        self.ensure_open()?;
        let address = address.get_u64().1 as usize;

        match unsafe {
            VirtualFreeEx(
                self.handle,
                address as *mut _,
                size as usize,
                VIRTUAL_FREE_TYPE(free_type),
            )
        } {
            Ok(_) => Ok(()),
            Err(err) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to free memory at 0x{:X}: {:?}", address, err)
            )),
        }
    }

    // ── Process Control ──

    #[napi]
    pub fn suspend_process(&self) -> Result<()> {
        self.ensure_open()?;
        let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) } {
            Ok(handle) => handle,
            Err(err) => return Err(Error::new(
                Status::GenericFailure,
                format!("Failed to create thread snapshot: {:?}", err)
            )),
        };

        let mut entry = THREADENTRY32::default();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        if let Err(err) = unsafe { Thread32First(snapshot, &mut entry) } {
            unsafe { CloseHandle(snapshot) }.ok();
            return Err(Error::new(Status::GenericFailure, format!("Failed to enumerate threads: {:?}", err)));
        }

        loop {
            if entry.th32OwnerProcessID == self.pid {
                if let Ok(thread) = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) } {
                    unsafe { SuspendThread(thread) };
                    unsafe { CloseHandle(thread) }.ok();
                }
            }
            if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
                break;
            }
        }

        unsafe { CloseHandle(snapshot) }.ok();
        Ok(())
    }

    #[napi]
    pub fn resume_process(&self) -> Result<()> {
        self.ensure_open()?;
        let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) } {
            Ok(handle) => handle,
            Err(err) => return Err(Error::new(
                Status::GenericFailure,
                format!("Failed to create thread snapshot: {:?}", err)
            )),
        };

        let mut entry = THREADENTRY32::default();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        if let Err(err) = unsafe { Thread32First(snapshot, &mut entry) } {
            unsafe { CloseHandle(snapshot) }.ok();
            return Err(Error::new(Status::GenericFailure, format!("Failed to enumerate threads: {:?}", err)));
        }

        loop {
            if entry.th32OwnerProcessID == self.pid {
                if let Ok(thread) = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) } {
                    unsafe { ResumeThread(thread) };
                    unsafe { CloseHandle(thread) }.ok();
                }
            }
            if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
                break;
            }
        }

        unsafe { CloseHandle(snapshot) }.ok();
        Ok(())
    }

    /// Creates a remote thread in the target process.
    /// Returns the thread exit code after waiting for completion.
    /// - `start_address`: address of the function to execute (e.g. LoadLibraryA or allocated shellcode)
    /// - `param`: optional parameter passed to the function (e.g. pointer to DLL path string)
    #[napi(js_name = "createRemoteThreadSync")]
    pub fn create_remote_thread(&self, start_address: BigInt, param: Option<BigInt>) -> Result<u32> {
        self.ensure_open()?;
        let start = start_address.get_u64().1 as usize;
        let param_val = param.map(|p| p.get_u64().1 as usize).unwrap_or(0);

        let thread_handle = match unsafe {
            CreateRemoteThread(
                self.handle,
                None,
                0,
                Some(std::mem::transmute(start)),
                Some(param_val as *const _),
                0,
                None,
            )
        } {
            Ok(handle) => handle,
            Err(err) => return Err(Error::new(
                Status::GenericFailure,
                format!("Failed to create remote thread at 0x{:X}: {:?}", start, err)
            )),
        };

        unsafe { WaitForSingleObject(thread_handle, 0xFFFFFFFF) };

        let mut exit_code: u32 = 0;
        let _ = unsafe {
            windows::Win32::System::Threading::GetExitCodeThread(thread_handle, &mut exit_code)
        };

        unsafe { CloseHandle(thread_handle) }.ok();
        Ok(exit_code)
    }

    /// Creates a remote thread without waiting for it to finish.
    /// Returns immediately. Useful for shellcode that runs indefinitely (hooks, loops).
    #[napi(js_name = "createRemoteThread")]
    pub fn create_remote_thread_async(&self, start_address: BigInt, param: Option<BigInt>) -> Result<()> {
        self.ensure_open()?;
        let start = start_address.get_u64().1 as usize;
        let param_val = param.map(|p| p.get_u64().1 as usize).unwrap_or(0);

        let thread_handle = match unsafe {
            CreateRemoteThread(
                self.handle,
                None,
                0,
                Some(std::mem::transmute(start)),
                Some(param_val as *const _),
                0,
                None,
            )
        } {
            Ok(handle) => handle,
            Err(err) => return Err(Error::new(
                Status::GenericFailure,
                format!("Failed to create remote thread at 0x{:X}: {:?}", start, err)
            )),
        };

        unsafe { CloseHandle(thread_handle) }.ok();
        Ok(())
    }

    // ── Batch Read ──

    #[napi]
    pub fn read_many(&self, requests: Vec<ReadRequest>) -> Result<Vec<Buffer>> {
        let mut results = Vec::with_capacity(requests.len());
        for req in &requests {
            let address = req.address.get_u64().1 as usize;
            let buffer = self.read_raw(address, req.size as usize)?;
            results.push(Buffer::from(buffer));
        }
        Ok(results)
    }

    // ── Lifecycle ──

    #[napi]
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        match unsafe { CloseHandle(self.handle) } {
            Ok(_) => {
                self.closed = true;
                Ok(())
            }
            Err(err) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to close process handle: {:?}", err),
            )),
        }
    }

    // ── Query ──

    #[napi]
    pub fn is_alive(&self) -> bool {
        if self.closed {
            return false;
        }
        let mut exit_code: u32 = 0;
        match unsafe { GetExitCodeProcess(self.handle, &mut exit_code) } {
            Ok(_) => exit_code == 259, // STILL_ACTIVE
            Err(_) => false,
        }
    }

    #[napi]
    pub fn get_module_export(&self, module_base: BigInt, func_name: String) -> Result<BigInt> {
        self.ensure_open()?;
        let base = module_base.get_u64().1 as usize;

        // DOS header
        let dos = self.read_raw(base, 64)?;
        if dos.len() < 64 || dos[0] != b'M' || dos[1] != b'Z' {
            return Err(Error::new(Status::InvalidArg, "Invalid DOS header"));
        }

        let e_lfanew = u32::from_le_bytes([dos[0x3C], dos[0x3D], dos[0x3E], dos[0x3F]]) as usize;

        // PE header
        let pe = self.read_raw(base + e_lfanew, 24)?;
        if pe.len() < 24 || pe[0] != b'P' || pe[1] != b'E' || pe[2] != 0 || pe[3] != 0 {
            return Err(Error::new(Status::InvalidArg, "Invalid PE signature"));
        }

        // Optional header magic → DataDirectory offset
        let opt_offset = base + e_lfanew + 24;
        let magic = self.read_raw(opt_offset, 2)?;
        let magic_val = u16::from_le_bytes([magic[0], magic[1]]);

        let data_dir_offset = match magic_val {
            0x20b => opt_offset + 112, // PE32+
            0x10b => opt_offset + 96,  // PE32
            _ => return Err(Error::new(Status::InvalidArg, "Unknown PE format")),
        };

        // Export directory RVA + size
        let entry = self.read_raw(data_dir_offset, 8)?;
        let export_rva = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]) as usize;

        if export_rva == 0 {
            return Err(Error::new(Status::GenericFailure, "Module has no export directory"));
        }

        // IMAGE_EXPORT_DIRECTORY (40 bytes)
        let ed = self.read_raw(base + export_rva, 40)?;
        if ed.len() < 40 {
            return Err(Error::new(Status::GenericFailure, "Failed to read export directory"));
        }

        let num_names = u32::from_le_bytes([ed[24], ed[25], ed[26], ed[27]]) as usize;
        let addr_funcs = u32::from_le_bytes([ed[28], ed[29], ed[30], ed[31]]) as usize;
        let addr_names = u32::from_le_bytes([ed[32], ed[33], ed[34], ed[35]]) as usize;
        let addr_ords = u32::from_le_bytes([ed[36], ed[37], ed[38], ed[39]]) as usize;

        // Read name RVA table + ordinal table
        let name_rvas = self.read_raw(base + addr_names, num_names * 4)?;
        let ordinals = self.read_raw(base + addr_ords, num_names * 2)?;

        for i in 0..num_names {
            let name_rva = u32::from_le_bytes([
                name_rvas[i * 4], name_rvas[i * 4 + 1], name_rvas[i * 4 + 2], name_rvas[i * 4 + 3]
            ]) as usize;

            let name_bytes = self.read_raw(base + name_rva, 256)?;
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
            let name = std::str::from_utf8(&name_bytes[..name_end]).unwrap_or("");

            if name == func_name {
                let ordinal = u16::from_le_bytes([ordinals[i * 2], ordinals[i * 2 + 1]]) as usize;
                let func_rva_bytes = self.read_raw(base + addr_funcs + ordinal * 4, 4)?;
                let func_rva = u32::from_le_bytes([
                    func_rva_bytes[0], func_rva_bytes[1], func_rva_bytes[2], func_rva_bytes[3]
                ]) as usize;

                return Ok(BigInt::from((base + func_rva) as u64));
            }
        }

        Err(Error::new(Status::GenericFailure, format!("Export '{}' not found", func_name)))
    }
}

impl Drop for OpenedProcess {
    fn drop(&mut self) {
        if !self.closed {
            unsafe { CloseHandle(self.handle) }.ok();
        }
    }
}

#[napi]
pub fn open_process(pid: u32, access_rights: ProcessAccessRights) -> Result<OpenedProcess> {
    match unsafe { OpenProcess(access_rights.into(), false, pid) } {
        Ok(handle) => Ok(
            OpenedProcess { handle, pid, closed: false }
        ),
        Err(err) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to open process {}: {:?}", pid, err)
        )),
    }
}

#[napi]
pub fn find_process(name: String) -> Result<Option<Process>> {
    let processes = enumerate_processes()?;
    Ok(processes.into_iter().find(|p| p.name.eq_ignore_ascii_case(&name)))
}

#[napi]
pub fn find_module(pid: u32, name: String) -> Result<Option<Module>> {
    let modules = enumerate_modules(pid)?;
    Ok(modules.into_iter().find(|m| m.name.eq_ignore_ascii_case(&name)))
}
