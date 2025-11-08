use anyhow::Result;
use rayon::prelude::*;
use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE, WIN32_ERROR, LUID},
        Security::{
            AdjustTokenPrivileges, CreateWellKnownSid, GetTokenInformation, LookupPrivilegeValueW,
            TokenElevation, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES,
            TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY, DACL_SECURITY_INFORMATION,
            LUID_AND_ATTRIBUTES, PSID, ACL, WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid,
        },
        Security::Authorization::{
            SetEntriesInAclW, SetNamedSecurityInfoW, ACCESS_MODE, EXPLICIT_ACCESS_W,
            NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_FORM, TRUSTEE_TYPE,
            TRUSTEE_W, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
        },
        Storage::FileSystem::{
            CreateFileW, DeleteFileW, FindClose, FindFirstFileExW, FindNextFileW, GetFileAttributesW,
            RemoveDirectoryW, SetFileAttributesW, SetFileInformationByHandle, WIN32_FIND_DATAW,
            FILE_DISPOSITION_INFO_EX, FILE_DISPOSITION_INFO_EX_FLAGS, FILE_DISPOSITION_FLAG_DELETE,
            FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
            FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_MODE,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FINDEX_INFO_LEVELS,
            FINDEX_SEARCH_OPS, FIND_FIRST_EX_FLAGS, FIND_FIRST_EX_LARGE_FETCH, OPEN_EXISTING,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
            FindExInfoBasic, FindExSearchNameMatch, FileDispositionInfoEx, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, DELETE,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

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

/// Try to enable useful privileges (names are PCWSTR constants like SE_BACKUP_NAME)
pub fn enable_privileges(names: &[PCWSTR]) -> Result<()> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token)?;
        for &name in names {
            let mut luid = LUID::default();
            LookupPrivilegeValueW(None, name, &mut luid)?;
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
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

/// Simple bottom-up walk
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

/// File or link delete. Uses POSIX semantics + ignore readonly. Retries with ACL fix if requested.
pub fn force_delete_file(path: &Path, fix_acl: bool, verbose: bool) -> Result<()> {
    clear_readonly(path).ok();

    let attrs: u32 = unsafe { GetFileAttributesW(pcw(path)) };
    let rp = attrs != u32::MAX && (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0;

    let desired: u32 = (DELETE | FILE_READ_ATTRIBUTES | FILE_GENERIC_WRITE).0;
    let share = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);
    let flags = if rp { FILE_FLAG_OPEN_REPARSE_POINT } else { FILE_FLAGS_AND_ATTRIBUTES(0) };

    let h = unsafe {
        match CreateFileW(pcw(path), desired, share, None, OPEN_EXISTING, flags, None) {
            Ok(h) => h,
            Err(e) => {
                if fix_acl {
                    take_ownership_and_grant_admins(path)?;
                    return force_delete_file(path, false, verbose);
                } else {
                    return Err(e.into());
                }
            }
        }
    };

    let mut ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
            FILE_DISPOSITION_FLAG_DELETE.0
                | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0
                | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE.0,
        ),
    };

    unsafe {
        match SetFileInformationByHandle(
            h,
            FileDispositionInfoEx,
            &mut ex as *mut _ as *const c_void,
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        ) {
            Ok(_) => CloseHandle(h)?,
            Err(_) => {
                CloseHandle(h)?;
                let _ = DeleteFileW(pcw(path));
            }
        }
    }

    if verbose {
        eprintln!("deleted file/link: {}", path.display());
    }
    Ok(())
}

/// Remove an empty directory or a directory reparse point
pub fn force_delete_dir(path: &Path, fix_acl: bool, verbose: bool) -> Result<()> {
    clear_readonly(path).ok();

    let attrs: u32 = unsafe { GetFileAttributesW(pcw(path)) };
    let is_rp = attrs != u32::MAX && (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0;

    let desired: u32 = (DELETE | FILE_READ_ATTRIBUTES).0;
    let share = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);
    let mut flags = FILE_FLAG_BACKUP_SEMANTICS;
    if is_rp {
        flags = FILE_FLAGS_AND_ATTRIBUTES(flags.0 | FILE_FLAG_OPEN_REPARSE_POINT.0);
    }

    let h = unsafe {
        match CreateFileW(pcw(path), desired, share, None, OPEN_EXISTING, flags, None) {
            Ok(h) => h,
            Err(e) => {
                if fix_acl {
                    take_ownership_and_grant_admins(path)?;
                    return force_delete_dir(path, false, verbose);
                } else {
                    let ok = RemoveDirectoryW(pcw(path));
                    if ok.is_err() {
                        return Err(e.into());
                    }
                    if verbose {
                        eprintln!("deleted dir: {}", path.display());
                    }
                    return Ok(());
                }
            }
        }
    };

    let mut ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
            FILE_DISPOSITION_FLAG_DELETE.0
                | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0
                | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE.0,
        ),
    };
    unsafe {
        match SetFileInformationByHandle(
            h,
            FileDispositionInfoEx,
            &mut ex as *mut _ as *const c_void,
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        ) {
            Ok(_) => CloseHandle(h)?,
            Err(_) => {
                CloseHandle(h)?;
                let _ = RemoveDirectoryW(pcw(path));
            }
        }
    }

    if verbose {
        eprintln!("deleted dir: {}", path.display());
    }
    Ok(())
}

fn clear_readonly(path: &Path) -> Result<()> {
    unsafe {
        let attrs: u32 = GetFileAttributesW(pcw(path));
        if attrs == u32::MAX {
            return Ok(());
        }
        if (attrs & FILE_ATTRIBUTE_READONLY.0) != 0 {
            SetFileAttributesW(
                pcw(path),
                FILE_FLAGS_AND_ATTRIBUTES(attrs & !FILE_ATTRIBUTE_READONLY.0),
            )?;
        }
    }
    Ok(())
}

/// Take ownership + grant BUILTIN\Administrators full control (GENERIC_ALL)
pub fn take_ownership_and_grant_admins(path: &Path) -> Result<()> {
    unsafe {
        let mut admins_sid_buf = [0u8; 68];
        let mut sid_len = admins_sid_buf.len() as u32;
        CreateWellKnownSid(
            WELL_KNOWN_SID_TYPE(WinBuiltinAdministratorsSid.0),
            None,
            PSID(admins_sid_buf.as_mut_ptr() as *mut _),
            &mut sid_len,
        )?;

        // EXPLICIT_ACCESS for GENERIC_ALL
        let mut ea = EXPLICIT_ACCESS_W::default();
        ea.grfAccessPermissions = 0x1000_0000 | 0x2000_0000 | 0x4000_0000 | 0x8000_0000; // GENERIC_ALL
        ea.grfAccessMode = ACCESS_MODE(1); // GRANT_ACCESS
        ea.grfInheritance = Default::default();

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

        let hr: WIN32_ERROR = SetNamedSecurityInfoW(
            pcw(path),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            PSID(admins_sid_buf.as_mut_ptr() as *mut _),
            PSID::default(),
            Some(new_dacl as *const ACL),
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
            let h = match FindFirstFileExW(
                pcw(&pattern),
                FINDEX_INFO_LEVELS(FindExInfoBasic.0),
                &mut data as *mut _ as *mut c_void,
                FINDEX_SEARCH_OPS(FindExSearchNameMatch.0),
                None,
                FIND_FIRST_EX_FLAGS(FIND_FIRST_EX_LARGE_FETCH.0),
            ) {
                Ok(h) => h,
                Err(_) => continue,
            };

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

fn pcw(p: &Path) -> PCWSTR {
    let mut v: Vec<u16> = p.as_os_str().encode_wide().collect();
    if v.is_empty() || *v.last().unwrap() != 0 {
        v.push(0);
    }
    PCWSTR(v.as_ptr())
}
