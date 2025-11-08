use anyhow::{Context, Result};
use rayon::prelude::*;
use std::{
    ffi::{c_void, OsStr},
    mem::{size_of, zeroed},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, BOOLEAN, HANDLE, WIN32_ERROR},
        Security::{
            AdjustTokenPrivileges, CreateWellKnownSid, GetTokenInformation, LookupPrivilegeValueW,
            TokenElevation, ACE_FLAGS, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES,
            TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY,
            SE_BACKUP_NAME, SE_RESTORE_NAME, SE_TAKE_OWNERSHIP_NAME,
        },
        Security::Authorization::{
            SetEntriesInAclW, SetNamedSecurityInfoW, ACCESS_MODE, EXPLICIT_ACCESS_W,
            NO_MULTIPLE_TRUSTEE, TRUSTEE_FORM, TRUSTEE_TYPE, TRUSTEE_W, DACL_SECURITY_INFORMATION,
            TRUSTEE_IS_SID, TRUSTEE_IS_USER,
        },
        Storage::FileSystem::{
            CreateFileW, DeleteFileW, FindClose, FindFirstFileExW, FindNextFileW, GetFileAttributesW,
            RemoveDirectoryW, SetFileAttributesW, SetFileInformationByHandle, WIN32_FIND_DATAW,
            FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX, FILE_DISPOSITION_INFO_EX_FLAGS,
            FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
            FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_WRITE,
            FILE_INFO_BY_HANDLE_CLASS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FINDEX_INFO_LEVELS, FINDEX_SEARCH_OPS,
            FIND_FIRST_EX_FLAGS, FIND_FIRST_EX_LARGE_FETCH, OPEN_EXISTING,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
            FindExInfoBasic, FindExSearchNameMatch, FileDispositionInfo, FileDispositionInfoEx,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

/// exportable constants for caller
pub const SE_BACKUP_NAME: PCWSTR = SE_BACKUP_NAME;
pub const SE_RESTORE_NAME: PCWSTR = SE_RESTORE_NAME;
pub const SE_TAKE_OWNERSHIP_NAME: PCWSTR = SE_TAKE_OWNERSHIP_NAME;

/// Keep UTF-16 buffer alive across Win32 calls
struct Wide(Vec<u16>);
impl Wide {
    fn from_os(s: &OsStr) -> Self {
        let mut v: Vec<u16> = s.encode_wide().collect();
        v.push(0);
        Self(v)
    }
    fn from_path(p: &Path) -> Self {
        Self::from_os(p.as_os_str())
    }
    fn pcw(&self) -> PCWSTR {
        PCWSTR(self.0.as_ptr())
    }
}

/// Add \\?\ or \\?\UNC\ to allow long paths
pub fn add_verbatim_prefix(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if s.starts_with(r"\\?\") {
        return p.to_path_buf();
    }
    if s.starts_with(r"\\") {
        let mut out = String::from(r"\\?\UNC\");
        out.push_str(&s[2..]);
        return PathBuf::from(out);
    }
    let mut out = String::from(r"\\?\");
    out.push_str(&s);
    PathBuf::from(out)
}

/// Strong elevation check
pub fn require_elevation() -> Result<()> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let mut elev: TOKEN_ELEVATION = zeroed();
        let mut ret_len = 0u32;
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )?;
        CloseHandle(token)?;
        if elev.TokenIsElevated == 0 {
            anyhow::bail!("not elevated");
        }
    }
    Ok(())
}

/// Try to enable useful privileges
pub fn enable_privileges(names: &[PCWSTR]) -> Result<()> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token)?;

        for &name in names {
            let mut luid = windows::Win32::Foundation::LUID::default();
            LookupPrivilegeValueW(None, name, &mut luid)?;

            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: TOKEN_PRIVILEGES_ATTRIBUTES(2), // SE_PRIVILEGE_ENABLED
                }],
            };

            AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)?;
        }
        CloseHandle(token)?;
    }
    Ok(())
}

/// Bottom-up delete using WalkDir (simple, safe)
pub fn force_delete_tree_walkdir(root: &Path, fix_acl: bool, verbose: bool) -> Result<()> {
    for entry in WalkDir::new(root).follow_links(false).contents_first(true) {
        let entry = entry?;
        let p = entry.path();
        if entry.file_type().is_dir() {
            force_delete_dir(p, fix_acl, verbose)?;
        } else {
            force_delete_file(p, fix_acl, verbose)?;
        }
    }
    Ok(())
}

/// SMB-optimized fast collector and parallel deleter
pub fn force_delete_tree_fast(root: &Path, fix_acl: bool, verbose: bool) -> Result<()> {
    let (files, mut dirs) = collect_tree_fast(root)?;
    files.par_iter().for_each(|f| {
        let _ = force_delete_file(f, fix_acl, verbose);
    });
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for d in dirs {
        let _ = force_delete_dir(&d, fix_acl, verbose);
    }
    Ok(())
}

/// Dry-run printing
pub fn dry_run_tree(root: &Path) -> Result<()> {
    let (files, mut dirs) = collect_tree_fast(root)?;
    for f in &files {
        eprintln!("[DRY] file: {}", f.display());
    }
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for d in &dirs {
        eprintln!("[DRY] dir:  {}", d.display());
    }
    Ok(())
}

/// Low-level delete a file or link. Tries POSIX + ignore-readonly.
pub fn force_delete_file(path: &Path, fix_acl: bool, verbose: bool) -> Result<()> {
    clear_readonly(path).ok();

    // For reparse points, open the link itself
    let attrs: u32 = unsafe { GetFileAttributesW(Wide::from_path(path).pcw()) };
    let rp = attrs != u32::MAX && (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0;

    let flags_attr = FILE_FLAGS_AND_ATTRIBUTES(0);
    let open_flags = if rp { FILE_FLAGS_AND_ATTRIBUTES(0x00200000) } else { FILE_FLAGS_AND_ATTRIBUTES(0) }; // FILE_FLAG_OPEN_REPARSE_POINT

    let h = unsafe {
        CreateFileW(
            Wide::from_path(path).pcw(),
            (windows::Win32::Storage::FileSystem::DELETE | FILE_READ_ATTRIBUTES | FILE_GENERIC_WRITE) as u32,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(open_flags.0 | flags_attr.0),
            None,
        )?
    };

    // Prefer Ex with POSIX semantics
    let mut ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
            FILE_DISPOSITION_FLAG_DELETE.0
                | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0
                | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE.0,
        ),
    };

    unsafe {
        SetFileInformationByHandle(
            h,
            FileDispositionInfoEx,
            &mut ex as *mut _ as *const c_void,
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )?;
        CloseHandle(h)?;
    }

    if verbose {
        eprintln!("deleted file/link: {}", path.display());
    }
    Ok(())
}

/// Remove an empty directory or a directory reparse point
pub fn force_delete_dir(path: &Path, fix_acl: bool, verbose: bool) -> Result<()> {
    clear_readonly(path).ok();

    let attrs: u32 = unsafe { GetFileAttributesW(Wide::from_path(path).pcw()) };
    let is_rp = attrs != u32::MAX && (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0;

    let base = 0x02000000; // FILE_FLAG_BACKUP_SEMANTICS
    let flags = if is_rp { base | 0x00200000 } else { base }; // + FILE_FLAG_OPEN_REPARSE_POINT

    let h = unsafe {
        CreateFileW(
            Wide::from_path(path).pcw(),
            (windows::Win32::Storage::FileSystem::DELETE | FILE_READ_ATTRIBUTES) as u32,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(flags),
            None,
        )?
    };

    let mut ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
            FILE_DISPOSITION_FLAG_DELETE.0
                | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0
                | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE.0,
        ),
    };
    unsafe {
        SetFileInformationByHandle(
            h,
            FileDispositionInfoEx,
            &mut ex as *mut _ as *const c_void,
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )?;
        CloseHandle(h)?;
    }

    if verbose {
        eprintln!("deleted dir: {}", path.display());
    }
    Ok(())
}

fn clear_readonly(path: &Path) -> Result<()> {
    unsafe {
        let w = Wide::from_path(path);
        let attrs: u32 = GetFileAttributesW(w.pcw());
        if attrs == u32::MAX {
            return Ok(());
        }
        if (attrs & FILE_ATTRIBUTE_READONLY.0) != 0 {
            SetFileAttributesW(w.pcw(), FILE_FLAGS_AND_ATTRIBUTES(attrs & !FILE_ATTRIBUTE_READONLY.0))?;
        }
    }
    Ok(())
}

/// Take ownership + grant BUILTIN\\Administrators full control (GENERIC_ALL)
pub fn take_ownership_and_grant_admins(path: &Path) -> Result<()> {
    unsafe {
        // Build Administrators SID
        let mut admins_sid_buf = [0u8; 68];
        let mut sid_len = admins_sid_buf.len() as u32;
        CreateWellKnownSid(
            windows::Win32::Security::WELL_KNOWN_SID_TYPE(windows::Win32::Security::WinBuiltinAdministratorsSid.0),
            None,
            windows::Win32::Security::PSID(admins_sid_buf.as_mut_ptr() as *mut _),
            &mut sid_len,
        )?;

        // EXPLICIT_ACCESS for GENERIC_ALL
        let mut ea = EXPLICIT_ACCESS_W::default();
        ea.grfAccessPermissions = 0x10000000 | 0x20000000 | 0x40000000 | 0x80000000; // GENERIC_ALL
        ea.grfAccessMode = ACCESS_MODE(1); // GRANT_ACCESS
        ea.grfInheritance = ACE_FLAGS(0);

        let mut trustee = TRUSTEE_W::default();
        trustee.pMultipleTrustee = std::ptr::null_mut();
        trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        trustee.TrusteeForm = TRUSTEE_FORM(TRUSTEE_IS_SID.0);
        trustee.TrusteeType = TRUSTEE_TYPE(TRUSTEE_IS_USER.0);
        trustee.ptstrName = PWSTR(admins_sid_buf.as_mut_ptr() as *mut _);
        ea.Trustee = trustee;

        let mut new_dacl = std::ptr::null_mut();
        let res: WIN32_ERROR = SetEntriesInAclW(Some(&[ea]), None, &mut new_dacl);
        if res != WIN32_ERROR(0) {
            anyhow::bail!("SetEntriesInAclW failed: win32={}", res.0);
        }

        // Set owner + DACL and protect DACL
        let hr: WIN32_ERROR = SetNamedSecurityInfoW(
            Wide::from_path(path).pcw() as *mut _,
            windows::Win32::Security::SE_OBJECT_TYPE::SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            windows::Win32::Security::PSID(admins_sid_buf.as_mut_ptr() as *mut _),
            None,
            new_dacl,
            None,
        );
        if hr != WIN32_ERROR(0) {
            anyhow::bail!("SetNamedSecurityInfoW failed: win32={}", hr.0);
        }
    }
    Ok(())
}

/// Faster non-recursive DFS with LARGE_FETCH, not following reparse points
fn collect_tree_fast(root: &Path) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut files = Vec::with_capacity(4096);
    let mut dirs = Vec::with_capacity(2048);

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        dirs.push(dir.clone());

        let mut pattern = dir.clone();
        pattern.push("*");

        unsafe {
            let mut data: WIN32_FIND_DATAW = zeroed();
            let h = FindFirstFileExW(
                Wide::from_path(&pattern).pcw(),
                FINDEX_INFO_LEVELS(FindExInfoBasic.0),
                &mut data as *mut _ as *mut c_void,
                FINDEX_SEARCH_OPS(FindExSearchNameMatch.0),
                None,
                FIND_FIRST_EX_FLAGS(FIND_FIRST_EX_LARGE_FETCH.0),
            )?;

            loop {
                let name = utf16z_to_string(&data.cFileName);
                if name != "." && name != ".." {
                    let mut p = dir.clone();
                    p.push(&name);

                    let attrs = data.dwFileAttributes;
                    let is_dir = (attrs & FILE_ATTRIBUTE_DIRECTORY.0) != 0;
                    let is_rp = (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0;

                    if is_dir && !is_rp {
                        stack.push(p);
                    } else {
                        files.push(p);
                    }
                }
                if FindNextFileW(h, &mut data).is_err() {
                    break;
                }
            }
            FindClose(h)?;
        }
    }
    Ok((files, dirs))
}

fn utf16z_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}
