//! Windows: ReadProcessMemory / WriteProcessMemory on the WowB.exe process started by the launcher.

use super::Memory;
use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE, STILL_ACTIVE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

pub struct ProcessMemory {
    pid: u32,
    handle: HANDLE,
}

unsafe impl Send for ProcessMemory {}

impl Drop for ProcessMemory {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

impl ProcessMemory {
    pub fn open(pid: u32) -> Option<Self> {
        let access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
        let handle = unsafe { OpenProcess(access, false, pid) }.ok()?;
        Some(Self { pid, handle })
    }

    pub fn rss(&self) -> u64 {
        let mut c = PROCESS_MEMORY_COUNTERS::default();
        unsafe {
            if GetProcessMemoryInfo(self.handle, &mut c, std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32).is_ok() {
                return c.WorkingSetSize as u64 / 4096;
            }
        }
        0
    }
}

impl Memory for ProcessMemory {
    fn regions(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut addr: usize = 0;
        loop {
            let mut info = MEMORY_BASIC_INFORMATION::default();
            let n = unsafe {
                VirtualQueryEx(self.handle, Some(addr as *const c_void), &mut info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>())
            };
            if n == 0 {
                break;
            }
            let base = info.BaseAddress as usize;
            let protect = info.Protect.0;
            let readable = protect & PAGE_GUARD.0 == 0
                && protect & PAGE_NOACCESS.0 == 0
                && [
                    PAGE_READONLY,
                    PAGE_READWRITE,
                    PAGE_WRITECOPY,
                    PAGE_EXECUTE_READ,
                    PAGE_EXECUTE_READWRITE,
                    PAGE_EXECUTE_WRITECOPY,
                ]
                .iter()
                .any(|p| protect & 0xFF == p.0);

            if info.State == MEM_COMMIT && info.Type == MEM_PRIVATE && readable {
                out.push((base as u64, (base + info.RegionSize) as u64));
            }
            let next = base.saturating_add(info.RegionSize);
            if next <= addr {
                break;
            }
            addr = next;
        }
        out
    }

    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut got = 0usize;
        unsafe {
            let _ = ReadProcessMemory(self.handle, addr as *const c_void, buf.as_mut_ptr() as *mut c_void, len, Some(&mut got));
        }
        if got == 0 {
            return None;
        }
        buf.truncate(got);
        Some(buf)
    }

    fn write(&self, addr: u64, data: &[u8]) -> bool {
        let mut written = 0usize;
        unsafe {
            WriteProcessMemory(self.handle, addr as *const c_void, data.as_ptr() as *const c_void, data.len(), Some(&mut written)).is_ok()
                && written == data.len()
        }
    }

    fn alive(&self) -> bool {
        let mut code = 0u32;
        unsafe { GetExitCodeProcess(self.handle, &mut code).is_ok() && code == STILL_ACTIVE.0 as u32 }
    }

    fn pid(&self) -> u32 {
        self.pid
    }
}

/// The running WowB.exe using the most memory.
pub fn find_client() -> Option<ProcessMemory> {
    let mut best: Option<(u64, ProcessMemory)> = None;
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut ok = Process32FirstW(snap, &mut entry).is_ok();
        while ok {
            let len = entry.szExeFile.iter().position(|c| *c == 0).unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
            if name.eq_ignore_ascii_case("WowB.exe") {
                if let Some(p) = ProcessMemory::open(entry.th32ProcessID) {
                    let rss = p.rss();
                    if best.as_ref().map_or(true, |(r, _)| rss > *r) {
                        best = Some((rss, p));
                    }
                }
            }
            ok = Process32NextW(snap, &mut entry).is_ok();
        }
        let _ = CloseHandle(snap);
    }
    best.map(|(_, p)| p)
}
