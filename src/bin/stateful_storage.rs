use clap::Parser;
use ethereum_types::{H160, H256};
use std::path::PathBuf;
use std::sync::Arc;

use yul2wasm::state_persistence::{
    CommitMode, DiffSink, StorageDiff, StorageProvider, StorageState,
};

#[derive(Parser)]
#[command(name = "stateful-storage")]
#[command(about = "Simulate persistence for dtvm storage diffs")]
struct Args {
    #[arg(
        long = "state-db",
        help = "Path to sled database directory",
        default_value = "state.db"
    )]
    state_db: PathBuf,
    #[arg(
        long = "state-mode",
        help = "Persistence mode (kvs|none)",
        default_value = "kvs"
    )]
    state_mode: String,
    #[arg(long = "diff-dump", help = "Optional JSONL diff dump path")]
    diff_dump: Option<PathBuf>,
    #[arg(
        long = "diff-commit",
        help = "When to flush diffs (end or each)",
        default_value = "end"
    )]
    diff_commit: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let commit_mode = match args.diff_commit.as_str() {
        "end" => CommitMode::End,
        "each" => CommitMode::Each,
        other => {
            eprintln!("Unknown commit mode {other}, falling back to end");
            CommitMode::End
        }
    };

    if args.state_mode.eq_ignore_ascii_case("none") {
        println!("Persistence disabled (state-mode=none); values are reset each run.");
        return Ok(());
    }

    let storage = Arc::new(StorageState::open(&args.state_db)?);
    let provider = StorageProvider::new(storage.clone());
    let mut sink = DiffSink::new(storage, commit_mode, args.diff_dump.clone());
    let address = H160::from_low_u64_be(0x4242);
    let slot = H256::from_low_u64_be(0x1);

    run_simulated_workflow(&mut sink, &provider, address, slot)?;
    Ok(())
}

fn run_simulated_workflow(
    sink: &mut DiffSink,
    provider: &StorageProvider,
    address: H160,
    slot: H256,
) -> anyhow::Result<()> {
    let initial_value = provider.sload(&address, &slot);
    println!("initial storage: {}", hex::encode(initial_value.as_bytes()));

    let diff1 = StorageDiff {
        address,
        key: slot,
        old_value: Some(initial_value),
        new_value: H256::from_low_u64_be(10),
    };
    sink.on_sstore(diff1)?;
    sink.on_finish()?;
    println!(
        "after first set: {}",
        hex::encode(provider.sload(&address, &slot).as_bytes())
    );

    let diff2 = StorageDiff {
        address,
        key: slot,
        old_value: Some(provider.sload(&address, &slot)),
        new_value: H256::from_low_u64_be(20),
    };
    sink.on_sstore(diff2)?;
    sink.on_finish()?;
    println!(
        "after second set: {}",
        hex::encode(provider.sload(&address, &slot).as_bytes())
    );

    Ok(())
}
