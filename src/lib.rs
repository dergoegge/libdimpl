use clap::Parser;
use libafl::{
    corpus::{InMemoryCorpus, NopCorpus},
    events::SimpleEventManager,
    executors::{DiffExecutor, ExitKind, InProcessExecutor},
    feedbacks::MaxMapFeedback,
    fuzzer::StdFuzzer,
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, StdMapObserver},
    schedulers::QueueScheduler,
    stages::StdMutationalStage,
    state::StdState,
    Fuzzer,
};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice};
use libafl_qemu::{
    edges::edges_max_num, edges::QemuEdgeCoverageClassicHelper, elf::EasyElf, ArchExtras,
    CallingConvention, Emulator, GuestAddr, GuestReg, MmapPerms, QemuExecutor, QemuHooks, Regs,
};
use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, DifferentialAFLMapSwapObserver,
};
use std::alloc::{alloc_zeroed, Layout};
use std::env;

#[derive(Parser, Debug)]
struct Options {
    //#[arg(
    //    long = "seeds",
    //    help = "Seed corpus directory (has to be non-empty)",
    //    required = true
    //)]
    //seeds: String,
    //#[arg(
    //    long = "solutions",
    //    help = "Directory in which solutions (crashes, timeouts, differential finds) will be stored",
    //    required = true
    //)]
    //solutions: String,
    #[arg(help = "Secondary binary to fuzz against under qemu")]
    secondary: String,
    #[arg(last = true, help = "Arguments passed to the target")]
    args: Vec<String>,
}

pub const MAX_INPUT_SIZE: usize = 1048576; // 1MB

#[no_mangle]
pub extern "C" fn libafl_main() {
    let mut options = Options::parse();
    let program = env::args().next().unwrap();
    options.args.insert(0, options.secondary);
    options.args.insert(0, program);

    // Setup QEMU
    env::remove_var("LD_LIBRARY_PATH");
    let env: Vec<(String, String)> = env::vars().collect();
    let emu = Emulator::new(&options.args, &env).unwrap();

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer).unwrap();

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", emu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");

    // Emulate until `LLVMFuzzerTestOneInput` is hit
    emu.entry_break(test_one_input_ptr);

    let ret_addr: GuestAddr = emu.read_return_address().unwrap();
    emu.set_breakpoint(ret_addr);

    let input_addr = emu
        .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
        .unwrap();

    let stack_ptr: GuestAddr = emu.read_reg(Regs::Sp).unwrap();

    // Allocate the edge map
    let num_edges: usize = edges_max_num();
    let edge_layout = Layout::from_size_align(num_edges * 2, 64).unwrap();
    let edges =
        unsafe { core::slice::from_raw_parts_mut(alloc_zeroed(edge_layout), num_edges * 2) };

    // We create a large edge map that is split into two smaller edge maps of equal size
    // (qemu-edges and host-edges). As the naming suggests, they individually collect coverage
    // feedback for the host execution and the qemu execution.
    let mut qemu_edges_observer =
        unsafe { StdMapObserver::from_mut_ptr("qemu-edges", edges.as_mut_ptr(), num_edges) };
    let mut host_edges_observer = unsafe {
        StdMapObserver::from_mut_ptr("host-edges", edges.as_mut_ptr().add(num_edges), num_edges)
    };

    // We need to swap libafl's edge map pointer in between the host and qemu executions to ensure
    // that coverage is collected into the respective maps. Libafl's DifferentialAFLMapSwapObserver
    // serves that purpose out of the box.
    let swap_observer =
        DifferentialAFLMapSwapObserver::new(&mut qemu_edges_observer, &mut host_edges_observer);

    // We use the combined edge map for coverage feedback in this differential fuzzer.
    let combined_edge_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::differential_from_mut_ptr(
            "combined-edges",
            edges.as_mut_ptr(),
            num_edges * 2,
        ))
    };
    let mut feedback = MaxMapFeedback::tracking(&combined_edge_observer, true, false);

    // TODO differential objectives
    let mut objective = ();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::new(),
        NopCorpus::new(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let scheduler = QueueScheduler::new();
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
        tuple_list!(qemu_edges_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
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
        tuple_list!(host_edges_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .unwrap();

    // Combine both executors into a `DiffExecutor`.
    let mut executor = DiffExecutor::new(
        host_executor,
        qemu_executor,
        tuple_list!(swap_observer, combined_edge_observer),
    );

    // Simple havoc mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // Initialize host in-process harness (QEMU harness is expected to that on its own).
    let args: Vec<String> = env::args().collect();
    if libfuzzer_initialize(&args) == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    if state.must_load_initial_inputs() {
        // We can't start from an empty corpus, so just generate a few random inputs.
        let mut generator = RandBytesGenerator::new(32);
        state
            .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
            .expect("Failed to generate the initial corpus");
    }

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
