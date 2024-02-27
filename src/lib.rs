use clap::Parser;
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::ProgressReporter,
    events::SimpleEventManager,
    executors::{DiffExecutor, ExitKind, InProcessExecutor},
    feedbacks::{differential::DiffResult, DiffFeedback, MaxMapFeedback},
    fuzzer::StdFuzzer,
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes, UsesInput},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, tokens_mutations, StdScheduledMutator, Tokens},
    observers::{HitcountsMapObserver, Observer, StdMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, HasMetadata, HasSolutions, StdState},
    Fuzzer,
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    tuples::{tuple_list, Merge},
    AsSlice, Named,
};
use libafl_qemu::{
    edges::edges_max_num, edges::QemuEdgeCoverageClassicHelper, elf::EasyElf, ArchExtras,
    CallingConvention, Emulator, GuestAddr, GuestReg, MmapPerms, QemuExecutor, QemuHooks, Regs,
};
use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer,
    DifferentialAFLMapSwapObserver,
};
use std::alloc::{alloc_zeroed, Layout};
use std::env;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Options {
    #[arg(
        long = "log-diff-values",
        help = "Log differential values for solutions"
    )]
    log_diff_values: bool,
    #[arg(
        long = "ignore-solutions",
        help = "Keep fuzzing even if a solution has already been found"
    )]
    ignore_solutions: bool,
    #[arg(long = "seeds", help = "Seed corpus directory", required = true)]
    seeds: String,
    #[arg(
        long = "solutions",
        help = "Directory in which solutions (differential finds) will be stored",
        required = true
    )]
    solutions: String,
    #[arg(long = "tokens", help = "Tokens file")]
    tokens: Option<String>,
    #[arg(help = "Secondary binary to fuzz against under qemu")]
    secondary: String,
    #[arg(last = true, help = "Arguments passed to the target")]
    args: Vec<String>,
}

pub const MAX_INPUT_SIZE: usize = 1048576; // 1MB

const MAX_DIFFERENTIAL_VALUE_SIZE: usize = 32;
// In-process differential value used for comparison with the qemu differential value.
static mut DIFFERENTIAL_VALUE: [u8; MAX_DIFFERENTIAL_VALUE_SIZE] =
    [0u8; MAX_DIFFERENTIAL_VALUE_SIZE];
// Export a pointer to the in-process differential value so that the harness can write to it.
//
// Note: An alternative (maybe better) approach would be to let the harness define the symbol and
// have this library link to it with `extern "C"`.
#[no_mangle]
pub static mut DIFFERENTIAL_VALUE_PTR: *mut u8 = unsafe { DIFFERENTIAL_VALUE.as_mut_ptr() };

#[derive(serde::Serialize, serde::Deserialize)]
struct QemuDifferentialValueObserver<'a> {
    name: String,
    last_value: Vec<u8>,
    #[serde(skip_serializing)]
    #[serde(skip_deserializing)]
    emu: Option<&'a Emulator>,
    differential_value_ptr: GuestAddr,
}

impl Named for QemuDifferentialValueObserver<'_> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<'a> QemuDifferentialValueObserver<'a> {
    fn new(name: &str, emu: &'a Emulator, differential_value_ptr: GuestAddr) -> Self {
        Self {
            name: String::from(name),
            last_value: vec![0u8; MAX_DIFFERENTIAL_VALUE_SIZE],
            emu: Some(emu),
            differential_value_ptr,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct HostDifferentialValueObserver {
    name: String,
    last_value: Vec<u8>,
}

impl HostDifferentialValueObserver {
    fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            last_value: vec![0u8; MAX_DIFFERENTIAL_VALUE_SIZE],
        }
    }
}

impl Named for HostDifferentialValueObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

// After each execution the `QemuDifferentialValueObserver` will read the differential value from
// emulator's memory.
impl<S> Observer<S> for QemuDifferentialValueObserver<'_>
where
    S: UsesInput,
{
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), libafl_bolts::Error> {
        unsafe {
            self.emu
                .unwrap()
                .read_mem(self.differential_value_ptr, self.last_value.as_mut_slice());
        }
        return Ok(());
    }
}

// After each execution the `HostDifferentialValueObserver` will read and store the differential
// value from `DIFFERENTIAL_VALUE`.
impl<S> Observer<S> for HostDifferentialValueObserver
where
    S: UsesInput,
{
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), libafl_bolts::Error> {
        unsafe {
            self.last_value
                .copy_from_slice(DIFFERENTIAL_VALUE.as_slice());
        }
        return Ok(());
    }
}

#[no_mangle]
pub extern "C" fn libafl_main() {
    let mut options = Options::parse();
    let program = env::args().next().unwrap();
    options.args.insert(0, options.secondary);
    options.args.insert(0, program);

    // Setup QEMU
    env::remove_var("LD_LIBRARY_PATH");
    println!("{:?}", &options.args);
    let env: Vec<(String, String)> = env::vars().collect();
    let emu = Emulator::new(&options.args, &env).unwrap();

    println!("{}", emu.binary_path());
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer).unwrap();

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", emu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");

    let diff_value_ptr = elf
        .resolve_symbol("DIFFERENTIAL_VALUE", emu.load_addr())
        .expect("Symbol DIFFERENTIAL_VALUE not found");

    // Emulate until `LLVMFuzzerTestOneInput` is hit
    emu.entry_break(test_one_input_ptr);

    let ret_addr: GuestAddr = emu.read_return_address().unwrap();
    emu.set_breakpoint(ret_addr);

    let input_addr = emu
        .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
        .unwrap();

    let stack_ptr: GuestAddr = emu.read_reg(Regs::Sp).unwrap();

    // Allocate an edge map for the qemu executions. This will be unused since we only care about
    // the coverage in the host execution (for now). We still need to have an edge map and observer
    // for the differential map swap observer.
    let num_edges: usize = edges_max_num();
    let edge_layout = Layout::from_size_align(num_edges, 64).unwrap();
    let edges = unsafe { core::slice::from_raw_parts_mut(alloc_zeroed(edge_layout), num_edges) };
    let mut unused_qemu_edges_observer =
        unsafe { StdMapObserver::from_mut_ptr("qemu-edges", edges.as_mut_ptr(), num_edges) };

    let mut host_edges_observer = unsafe { std_edges_map_observer("host-edges") };

    // We need to swap libafl's edge map pointer in between the host and qemu executions to ensure
    // that coverage is collected into the respective maps. Libafl's DifferentialAFLMapSwapObserver
    // serves that purpose out of the box.
    let swap_observer = DifferentialAFLMapSwapObserver::new(
        &mut unused_qemu_edges_observer,
        &mut host_edges_observer,
    );

    let host_hitcount_observer = HitcountsMapObserver::new(host_edges_observer);
    let mut feedback = MaxMapFeedback::tracking(&host_hitcount_observer, true, false);

    // Create two observers (one for each environment) that observe the state of
    // `DIFFERENTIAL_VALUE` after each execution. The host observer simply reads from the in-memory
    // `DIFFERENTIAL_VALUE`, while the qemu observer reads the required memory from the emulator.
    let host_diff_value_observer = HostDifferentialValueObserver::new("host-diff-value-observer");
    let qemu_diff_value_observer =
        QemuDifferentialValueObserver::new("qemu-diff-value-observer", &emu, diff_value_ptr);
    // Both observers are combined into a `DiffFeedback` that compares the retrieved values from
    // the two observers described above.
    let mut objective = DiffFeedback::new(
        "diff-value-feedback",
        &host_diff_value_observer,
        &qemu_diff_value_observer,
        |o1, o2| {
            if o1.last_value == o2.last_value {
                DiffResult::Equal
            } else {
                if options.log_diff_values {
                    println!(
                        "{:x?} != {:x?}",
                        o1.last_value.as_slice(),
                        o2.last_value.as_slice()
                    );
                }

                DiffResult::Diff
            }
        },
    )
    .unwrap();

    let seed_dir_path = PathBuf::from(options.seeds);
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryOnDiskCorpus::new(&seed_dir_path).unwrap(),
        OnDiskCorpus::new(PathBuf::from(options.solutions)).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut hooks = QemuHooks::new(
        emu.clone(),
        // TODO: The classic helper is needed for StdMapObserver. Can we do differential fuzzing with a
        // VariableMapObserver? (should be faster)
        tuple_list!(QemuEdgeCoverageClassicHelper::default(),),
    );

    // Simple monitor for printing user-facing statistics.
    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);

    // Setup QEMU in-process executor

    let mut qemu_harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > MAX_INPUT_SIZE {
            buf = &buf[0..MAX_INPUT_SIZE];
            len = MAX_INPUT_SIZE;
        }
        let len = len as GuestReg;

        unsafe {
            emu.write_mem(input_addr, buf);
            emu.write_reg(Regs::Pc, test_one_input_ptr).unwrap();
            emu.write_reg(Regs::Sp, stack_ptr).unwrap();
            emu.write_return_address(ret_addr).unwrap();
            emu.write_function_argument(CallingConvention::Cdecl, 0, input_addr)
                .unwrap();
            emu.write_function_argument(CallingConvention::Cdecl, 1, len)
                .unwrap();
            // TODO handle emulation results?
            let _ = emu.run();
        }

        ExitKind::Ok
    };

    let qemu_executor = QemuExecutor::new(
        &mut hooks,
        &mut qemu_harness,
        tuple_list!(qemu_diff_value_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        std::time::Duration::from_millis(1000),
    )
    .unwrap();

    // Setup host in-process executor

    let mut host_harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        libfuzzer_test_one_input(buf);
        ExitKind::Ok
    };

    let host_executor = InProcessExecutor::new(
        &mut host_harness,
        tuple_list!(host_hitcount_observer, host_diff_value_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .unwrap();

    // Combine both executors into a `DiffExecutor`.
    let mut executor = DiffExecutor::new(host_executor, qemu_executor, tuple_list!(swap_observer));

    // Load tokens from file (if provided)
    let mut tokens = Tokens::new();
    if let Some(tokens_file) = &options.tokens {
        tokens.add_from_file(tokens_file).unwrap();
        state.add_metadata(tokens);
    }

    let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // Initialize host in-process harness (QEMU harness is expected to that on its own).
    if libfuzzer_initialize(&options.args[2..]) == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir_path])
            .expect("Failed to load inputs from disk");

        println!("Loaded {} seeds from disk", state.corpus().count());

        if state.corpus().count() == 0 {
            // We can't start from an empty corpus, so just generate a few random inputs.
            let mut generator = RandBytesGenerator::new(32);
            state
                .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 1024)
                .expect("Failed to generate the initial corpus");
            println!("Generated {} seeds randomly", state.corpus().count());
        }
    }

    loop {
        mgr.maybe_report_progress(&mut state, std::time::Duration::from_secs(15))
            .unwrap();
        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");

        if !options.ignore_solutions && state.solutions().count() != 0 {
            eprintln!("Found differential solution");
            std::process::exit(71);
        }
    }
}
