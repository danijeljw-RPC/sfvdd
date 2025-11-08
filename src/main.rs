mod win_delete;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use windows::Win32::Security::{SE_BACKUP_NAME, SE_RESTORE_NAME, SE_TAKE_OWNERSHIP_NAME};

#[derive(Parser, Debug)]
#[command(name = "sfvdd", about = "Super Fast Very Dangerous Delete (Windows)")]
struct Cli {
    /// --path="C:\\path\\to\\dir-or-file"
    #[arg(long, value_name = "PATH")]
    path: PathBuf,

    /// Be chatty
    #[arg(long)]
    verbose: bool,

    /// Take ownership + grant BUILTIN\Administrators on ACCESS_DENIED
    #[arg(long)]
    fix_acl: bool,

    /// Parallel SMB-optimized walk using FindFirstFileExW(LARGE_FETCH)
    #[arg(long)]
    fast: bool,

    /// Max parallel workers when --fast is set
    #[arg(long)]
    threads: Option<usize>,

    /// Print what would be deleted
    #[arg(long)]
    dry_run: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(n) = cli.threads {
        std::env::set_var("RAYON_NUM_THREADS", n.to_string());
    }

    win_delete::require_elevation().context("elevation required")?;

    // Best-effort privilege enablement
    let _ = win_delete::enable_privileges(&[SE_BACKUP_NAME, SE_RESTORE_NAME, SE_TAKE_OWNERSHIP_NAME]);

    let path = win_delete::add_verbatim_prefix(&cli.path);
    let meta = std::fs::symlink_metadata(&path)
        .with_context(|| format!("stat {}", path.display()))?;

    if cli.dry_run {
        eprintln!("[DRY-RUN] No files will be deleted.");
        if meta.is_dir() {
            win_delete::dry_run_tree(&path)?;
        } else {
            eprintln!("[DRY] file: {}", path.display());
        }
        return Ok(());
    }

    if meta.is_file() || meta.file_type().is_symlink() {
        win_delete::force_delete_file(&path, cli.fix_acl, cli.verbose)
    } else if meta.is_dir() {
        if cli.fast {
            win_delete::force_delete_tree_fast(&path, cli.fix_acl, cli.verbose)
        } else {
            win_delete::force_delete_tree_walkdir(&path, cli.fix_acl, cli.verbose)
        }
    } else {
        anyhow::bail!("unsupported file type: {}", path.display());
    }
}
