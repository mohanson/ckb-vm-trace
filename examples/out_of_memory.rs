use ckb_vm_trace::{Bytes, PProfLogger, PProfMachine};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fl_bin = "res/out_of_memory";

    let code_data = std::fs::read(fl_bin)?;
    let code = Bytes::from(code_data);

    let default_core_machine = ckb_vm::DefaultCoreMachine::<u64, ckb_vm::SparseMemory<u64>>::new(
        ckb_vm::ISA_IMC | ckb_vm::ISA_B,
        ckb_vm::machine::VERSION1,
        1 << 32,
    );
    let default_machine_builder = ckb_vm::DefaultMachineBuilder::new(default_core_machine);
    let default_machine = default_machine_builder.build();
    let pprof_func_provider = Box::new(PProfLogger::from_bytes(code.clone())?);
    let mut machine = PProfMachine::new(default_machine, pprof_func_provider);
    let args = vec![];
    // args.append(&mut fl_arg.iter().map(|x| Bytes::from(x.to_string())).collect());
    machine.load_program(&code, &args).unwrap();
    machine.run()?;

    Ok(())
}
