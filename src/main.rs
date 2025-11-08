mod win_delete;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "sfvdd", about = "Super Fast Very Dangerous Delete (Windows)")]
struct Cli {
    /// --path="C:\\path\\to\\dir-or-file"
    #[arg(long, value_name = "PATH")]
    path: PathBuf,

    /// Be chatty
    #[arg(long)]
    verbose: bool,

    /// Try to take ownership + grant BUILTIN\\Administrators on ACCESS_DENIED
    #[arg(long)]
    fix_acl: bool,

    /// Parallel SMB-aware fast walk using FindFirstFileExW(LARGE_FETCH)
    #[arg(long)]
    fast: bool,

    /// Max parallel workers for --fast. Default = Rayon auto.
    #[arg(long)]
    threads: Option<usize>,

    /// Dry run: print what would be deleted
    #[arg(long)]
    dry_run: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(n) = cli.threads {
        std::env::set_var("RAYON_NUM_THREADS", n.to_string());
    }

    win_delete::require_elevation().context("elevation required")?;

    // Enable useful privileges. Non-fatal if some fail.
    let _ = win_delete::enable_privileges(&[
        win_delete::SE_BACKUP_NAME,
        win_delete::SE_RESTORE_NAME,
        win_delete::SE_TAKE_OWNERSHIP_NAME,
    ]);

    let path = win_delete::add_verbatim_prefix(&cli.path);
    let meta = std::fs::symlink_metadata(&path)
        .with_context(|| format!("stat {}", path.display()))?;

    if cli.dry_run {
        eprintln!("[DRY-RUN] No files will be deleted.");
    }

    if meta.is_file() || meta.file_type().is_symlink() {
        if cli.dry_run {
            eprintln!("Would delete file: {}", path.display());
            return Ok(());
        }
        win_delete::force_delete_file(&path, cli.fix_acl, cli.verbose)
    } else if meta.is_dir() {
        if cli.dry_run {
            win_delete::dry_run_tree(&path)?;
            return Ok(());
        }
        if cli.fast {
            win_delete::force_delete_tree_fast(&path, cli.fix_acl, cli.verbose)
        } else {
            win_delete::force_delete_tree_walkdir(&path, cli.fix_acl, cli.verbose)
        }
    } else {
        anyhow::bail!("Unsupported file type: {}", path.display());
    }
}
