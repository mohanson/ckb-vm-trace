use ckb_vm::{
    instructions::{extract_opcode, insts},
    Instruction,
};

pub fn instruction_cycles(i: Instruction) -> u64 {
    match extract_opcode(i) {
        insts::OP_JALR => 3,
        insts::OP_LD => 2,
        insts::OP_LW => 3,
        insts::OP_LH => 3,
        insts::OP_LB => 3,
        insts::OP_LWU => 3,
        insts::OP_LHU => 3,
        insts::OP_LBU => 3,
        insts::OP_SB => 3,
        insts::OP_SH => 3,
        insts::OP_SW => 3,
        insts::OP_SD => 2,
        insts::OP_BEQ => 3,
        insts::OP_BGE => 3,
        insts::OP_BGEU => 3,
        insts::OP_BLT => 3,
        insts::OP_BLTU => 3,
        insts::OP_BNE => 3,
        insts::OP_EBREAK => 500,
        insts::OP_ECALL => 500,
        insts::OP_JAL => 3,
        insts::OP_RVC_LW => 3,
        insts::OP_RVC_LD => 2,
        insts::OP_RVC_SW => 3,
        insts::OP_RVC_SD => 2,
        insts::OP_RVC_LWSP => 3,
        insts::OP_RVC_LDSP => 2,
        insts::OP_RVC_SWSP => 3,
        insts::OP_RVC_SDSP => 2,
        insts::OP_RVC_BEQZ => 3,
        insts::OP_RVC_BNEZ => 3,
        insts::OP_RVC_JAL => 3,
        insts::OP_RVC_J => 3,
        insts::OP_RVC_JR => 3,
        insts::OP_RVC_JALR => 3,
        insts::OP_RVC_EBREAK => 500,
        insts::OP_MUL => 5,
        insts::OP_MULW => 5,
        insts::OP_MULH => 5,
        insts::OP_MULHU => 5,
        insts::OP_MULHSU => 5,
        insts::OP_DIV => 32,
        insts::OP_DIVW => 32,
        insts::OP_DIVU => 32,
        insts::OP_DIVUW => 32,
        insts::OP_REM => 32,
        insts::OP_REMW => 32,
        insts::OP_REMU => 32,
        insts::OP_REMUW => 32,
        // B extension
        insts::OP_CLZ => 1,
        insts::OP_CLZW => 1,
        insts::OP_CTZ => 1,
        insts::OP_CTZW => 1,
        insts::OP_PCNT => 1,
        insts::OP_PCNTW => 1,
        insts::OP_ANDN => 2,
        insts::OP_ORN => 2,
        insts::OP_XNOR => 2,
        insts::OP_PACK => 3,
        insts::OP_PACKU => 3,
        insts::OP_PACKH => 3,
        insts::OP_PACKW => 3,
        insts::OP_PACKUW => 3,
        insts::OP_MIN => 1,
        insts::OP_MINU => 1,
        insts::OP_MAX => 1,
        insts::OP_MAXU => 1,
        insts::OP_SEXTB => 1,
        insts::OP_SEXTH => 1,
        insts::OP_SBSET => 1,
        insts::OP_SBSETI => 1,
        insts::OP_SBSETW => 1,
        insts::OP_SBSETIW => 1,
        insts::OP_SBCLR => 1,
        insts::OP_SBCLRI => 1,
        insts::OP_SBCLRW => 1,
        insts::OP_SBCLRIW => 1,
        insts::OP_SBINV => 1,
        insts::OP_SBINVI => 1,
        insts::OP_SBINVW => 1,
        insts::OP_SBINVIW => 1,
        insts::OP_SBEXT => 1,
        insts::OP_SBEXTI => 1,
        insts::OP_SBEXTW => 1,
        insts::OP_SLO => 3,
        insts::OP_SLOI => 3,
        insts::OP_SLOW => 3,
        insts::OP_SLOIW => 3,
        insts::OP_SRO => 3,
        insts::OP_SROI => 3,
        insts::OP_SROW => 3,
        insts::OP_SROIW => 3,
        insts::OP_ROR => 1,
        insts::OP_RORI => 1,
        insts::OP_RORW => 1,
        insts::OP_RORIW => 1,
        insts::OP_ROL => 1,
        insts::OP_ROLW => 1,
        insts::OP_GREV => 64,
        insts::OP_GREVI => 64,
        insts::OP_GREVW => 64,
        insts::OP_GREVIW => 64,
        insts::OP_SHFL => 64,
        insts::OP_UNSHFL => 64,
        insts::OP_SHFLI => 64,
        insts::OP_UNSHFLI => 64,
        insts::OP_SHFLW => 64,
        insts::OP_UNSHFLW => 64,
        insts::OP_GORC => 64,
        insts::OP_GORCI => 64,
        insts::OP_GORCW => 64,
        insts::OP_GORCIW => 64,
        insts::OP_BFP => 64,
        insts::OP_BFPW => 64,
        insts::OP_BEXT => 64,
        insts::OP_BEXTW => 64,
        insts::OP_BDEP => 64,
        insts::OP_BDEPW => 64,
        insts::OP_CLMUL => 64,
        insts::OP_CLMULW => 64,
        insts::OP_CLMULH => 64,
        insts::OP_CLMULHW => 64,
        insts::OP_CLMULR => 64,
        insts::OP_CLMULRW => 64,
        insts::OP_CRC32B => 72,
        insts::OP_CRC32H => 72,
        insts::OP_CRC32W => 72,
        insts::OP_CRC32CB => 72,
        insts::OP_CRC32CH => 72,
        insts::OP_CRC32CW => 72,
        insts::OP_CRC32D => 72,
        insts::OP_CRC32CD => 72,
        insts::OP_BMATOR => 160,
        insts::OP_BMATXOR => 160,
        insts::OP_BMATFLIP => 160,
        insts::OP_CMIX => 4,
        insts::OP_CMOV => 2,
        insts::OP_FSL => 12,
        insts::OP_FSLW => 12,
        insts::OP_FSR => 12,
        insts::OP_FSRW => 12,
        insts::OP_FSRI => 12,
        insts::OP_FSRIW => 12,
        insts::OP_SH1ADD => 2,
        insts::OP_SH2ADD => 2,
        insts::OP_SH3ADD => 2,
        insts::OP_SH1ADDUW => 2,
        insts::OP_SH2ADDUW => 2,
        insts::OP_SH3ADDUW => 2,
        insts::OP_ADDWU => 1,
        insts::OP_SUBWU => 1,
        insts::OP_ADDIWU => 1,
        insts::OP_ADDUW => 1,
        insts::OP_SUBUW => 1,
        insts::OP_SLLIUW => 1,
        _ => 1,
    }
}