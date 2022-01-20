use crate::melvm::consts::{
    OPCODE_ADD, OPCODE_AND, OPCODE_BAPPEND, OPCODE_BCONS, OPCODE_BEMPTY, OPCODE_BEZ,
    OPCODE_BLENGTH, OPCODE_BNZ, OPCODE_BPUSH, OPCODE_BREF, OPCODE_BSET, OPCODE_BSLICE, OPCODE_BTOI,
    OPCODE_DIV, OPCODE_DUP, OPCODE_EQL, OPCODE_EXP, OPCODE_GT, OPCODE_HASH, OPCODE_ITOB,
    OPCODE_JMP, OPCODE_LOAD, OPCODE_LOADIMM, OPCODE_LOOP, OPCODE_LT, OPCODE_MUL, OPCODE_NOOP,
    OPCODE_NOT, OPCODE_OR, OPCODE_PUSHB, OPCODE_PUSHI, OPCODE_PUSHIC, OPCODE_REM, OPCODE_SHL,
    OPCODE_SHR, OPCODE_SIGEOK, OPCODE_STORE, OPCODE_STOREIMM, OPCODE_SUB, OPCODE_TYPEQ,
    OPCODE_VAPPEND, OPCODE_VCONS, OPCODE_VEMPTY, OPCODE_VLENGTH, OPCODE_VPUSH, OPCODE_VREF,
    OPCODE_VSET, OPCODE_VSLICE, OPCODE_XOR, OPCODE_OFLO, OPCODE_CLOFLO,
};

use std::{fmt::Display, io::Write};

use ethnum::U256;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
pub enum OpCode {
    Noop,
    // arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Exp(u8),
    // logic
    And,
    Or,
    Xor,
    Not,
    Eql,
    Lt,
    Gt,
    Shl,
    Shr,
    // cryptographyy
    Hash(u16),
    //SIGE,
    //SIGQ,
    SigEOk(u16),
    //SIGQOK,
    // "heap" access
    Store,
    Load,
    StoreImm(u16),
    LoadImm(u16),
    // vector operations
    VRef,
    VAppend,
    VEmpty,
    VLength,
    VSlice,
    VSet,
    VPush,
    VCons,
    // bytes operations
    BRef,
    BAppend,
    BEmpty,
    BLength,
    BSlice,
    BSet,
    BPush,
    BCons,

    // control flow
    Bez(u16),
    Bnz(u16),
    Jmp(u16),
    // Loop(iterations, instructions)
    Loop(u16, u16),

    // type conversions
    ItoB,
    BtoI,
    TypeQ,
    // SERIAL(u16),

    // literals
    PushB(Vec<u8>),
    PushI(U256),
    PushIC(U256),

    // Overflow
    Oflo,
    Cloflo,

    // duplication
    Dup,
}

#[derive(Error, Debug, Clone)]
pub enum ParseOpCodeError {
    #[error("invalid opcode")]
    InvalidOpcode,
}

impl Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpCode::Noop => "noop".fmt(f),
            OpCode::Add => "add".fmt(f),
            OpCode::Sub => "sub".fmt(f),
            OpCode::Mul => "mul".fmt(f),
            OpCode::Div => "div".fmt(f),
            OpCode::Exp(k) => format!("exp {}", k).fmt(f),
            OpCode::Rem => "rem".fmt(f),
            OpCode::And => "and".fmt(f),
            OpCode::Or => "or".fmt(f),
            OpCode::Xor => "xor".fmt(f),
            OpCode::Not => "not".fmt(f),
            OpCode::Eql => "eql".fmt(f),
            OpCode::Lt => "lt".fmt(f),
            OpCode::Gt => "gt".fmt(f),
            OpCode::Shl => "shl".fmt(f),
            OpCode::Shr => "shr".fmt(f),
            OpCode::Hash(i) => format!("hash {}", i).fmt(f),
            OpCode::SigEOk(i) => format!("sigeok {}", i).fmt(f),
            OpCode::Store => "store".fmt(f),
            OpCode::Load => "load".fmt(f),
            OpCode::StoreImm(i) => format!("storeimm {}", i).fmt(f),
            OpCode::LoadImm(i) => format!("loadimm {}", i).fmt(f),
            OpCode::VRef => "vref".fmt(f),
            OpCode::VAppend => "vappend".fmt(f),
            OpCode::VEmpty => "vempty".fmt(f),
            OpCode::VLength => "vlength".fmt(f),
            OpCode::VSlice => "vslice".fmt(f),
            OpCode::VSet => "vset".fmt(f),
            OpCode::VPush => "vpush".fmt(f),
            OpCode::VCons => "vcons".fmt(f),
            OpCode::BRef => "bref".fmt(f),
            OpCode::BAppend => "bappend".fmt(f),
            OpCode::BEmpty => "bempty".fmt(f),
            OpCode::BLength => "blength".fmt(f),
            OpCode::BSlice => "bslice".fmt(f),
            OpCode::BSet => "bset".fmt(f),
            OpCode::BPush => "bpush".fmt(f),
            OpCode::BCons => "bcons".fmt(f),
            OpCode::Bez(i) => format!("bez {}", i).fmt(f),
            OpCode::Bnz(i) => format!("bnz {}", i).fmt(f),
            OpCode::Jmp(i) => format!("jmp {}", i).fmt(f),
            OpCode::Loop(i, j) => format!("loop {} {}", i, j).fmt(f),
            OpCode::ItoB => "itob".fmt(f),
            OpCode::BtoI => "btoi".fmt(f),
            OpCode::TypeQ => "typeq".fmt(f),
            OpCode::PushB(v) => format!("pushb {}", hex::encode(&v)).fmt(f),
            OpCode::PushI(i) => format!("pushi {}", i).fmt(f),
            OpCode::PushIC(i) => format!("pushic {}", i).fmt(f),
            OpCode::Dup => "dup".fmt(f),
            OpCode::Oflo => "oflo".fmt(f),
            OpCode::Cloflo => "cloflo".fmt(f),
        }
    }
}

/// Opcode encoding error
#[derive(Error, Debug)]
pub enum EncodeError {
    #[error("PushB has too many bytes")]
    TooManyBytes,
}

/// Opcode decoding error
#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("I/O error: {0:?}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid opcode {0}")]
    InvalidOpcode(u8),
    #[error("Malformed varint")]
    InvalidVarint,
}

fn read_byte<T: std::io::Read>(input: &mut T) -> std::io::Result<u8> {
    let mut buffer: [u8; 1] = [0; 1];

    input.read_exact(&mut buffer)?;

    Ok(buffer[0])
}

impl OpCode {
    /// Encodes an opcode.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut output = Vec::new();

        match self {
            OpCode::Noop => output.write_all(&[OPCODE_NOOP]).unwrap(),

            OpCode::Add => output.write_all(&[OPCODE_ADD]).unwrap(),
            OpCode::Sub => output.write_all(&[OPCODE_SUB]).unwrap(),
            OpCode::Mul => output.write_all(&[OPCODE_MUL]).unwrap(),
            OpCode::Div => output.write_all(&[OPCODE_DIV]).unwrap(),
            OpCode::Rem => output.write_all(&[OPCODE_REM]).unwrap(),
            OpCode::Exp(k) => {
                output.write_all(&[OPCODE_EXP]).unwrap();
                output.write_all(&k.to_be_bytes()).unwrap();
            }

            OpCode::And => output.write_all(&[OPCODE_AND]).unwrap(),
            OpCode::Or => output.write_all(&[OPCODE_OR]).unwrap(),
            OpCode::Xor => output.write_all(&[OPCODE_XOR]).unwrap(),
            OpCode::Not => output.write_all(&[OPCODE_NOT]).unwrap(),
            OpCode::Eql => output.write_all(&[OPCODE_EQL]).unwrap(),

            OpCode::Lt => output.write_all(&[OPCODE_LT]).unwrap(),
            OpCode::Gt => output.write_all(&[OPCODE_GT]).unwrap(),
            OpCode::Shl => output.write_all(&[OPCODE_SHL]).unwrap(),
            OpCode::Shr => output.write_all(&[OPCODE_SHR]).unwrap(),

            OpCode::Hash(i) => {
                output.write_all(&[OPCODE_HASH]).unwrap();
                output.write_all(&i.to_be_bytes()).unwrap()
            }
            OpCode::SigEOk(i) => {
                output.write_all(&[OPCODE_SIGEOK]).unwrap();
                output.write_all(&i.to_be_bytes()).unwrap()
            }

            OpCode::Load => output.write_all(&[OPCODE_LOAD]).unwrap(),
            OpCode::Store => output.write_all(&[OPCODE_STORE]).unwrap(),
            OpCode::LoadImm(i) => {
                output.write_all(&[OPCODE_LOADIMM]).unwrap();
                output.write_all(&i.to_be_bytes()).unwrap()
            }
            OpCode::StoreImm(i) => {
                output.write_all(&[OPCODE_STOREIMM]).unwrap();
                output.write_all(&i.to_be_bytes()).unwrap()
            }

            OpCode::VRef => output.write_all(&[OPCODE_VREF]).unwrap(),
            OpCode::VAppend => output.write_all(&[OPCODE_VAPPEND]).unwrap(),
            OpCode::VEmpty => output.write_all(&[OPCODE_VEMPTY]).unwrap(),
            OpCode::VLength => output.write_all(&[OPCODE_VLENGTH]).unwrap(),
            OpCode::VSlice => output.write_all(&[OPCODE_VSLICE]).unwrap(),
            OpCode::VSet => output.write_all(&[OPCODE_VSET]).unwrap(),
            OpCode::VPush => output.write_all(&[OPCODE_VPUSH]).unwrap(),
            OpCode::VCons => output.write_all(&[OPCODE_VCONS]).unwrap(),

            OpCode::BRef => output.write_all(&[OPCODE_BREF]).unwrap(),
            OpCode::BAppend => output.write_all(&[OPCODE_BAPPEND]).unwrap(),
            OpCode::BEmpty => output.write_all(&[OPCODE_BEMPTY]).unwrap(),
            OpCode::BLength => output.write_all(&[OPCODE_BLENGTH]).unwrap(),
            OpCode::BSlice => output.write_all(&[OPCODE_BSLICE]).unwrap(),
            OpCode::BSet => output.write_all(&[OPCODE_BSET]).unwrap(),
            OpCode::BPush => output.write_all(&[OPCODE_BPUSH]).unwrap(),
            OpCode::BCons => output.write_all(&[OPCODE_BCONS]).unwrap(),

            OpCode::Jmp(i) => {
                output.write_all(&[OPCODE_JMP]).unwrap();
                output.write_all(&i.to_be_bytes()).unwrap()
            }
            OpCode::Bez(i) => {
                output.write_all(&[OPCODE_BEZ]).unwrap();
                output.write_all(&i.to_be_bytes()).unwrap()
            }
            OpCode::Bnz(i) => {
                output.write_all(&[OPCODE_BNZ]).unwrap();
                output.write_all(&i.to_be_bytes()).unwrap()
            }
            OpCode::Loop(iter, count) => {
                output.write_all(&[OPCODE_LOOP]).unwrap();
                output.write_all(&iter.to_be_bytes()).unwrap();
                output.write_all(&count.to_be_bytes()).unwrap()
            }

            OpCode::BtoI => output.write_all(&[OPCODE_BTOI]).unwrap(),
            OpCode::ItoB => output.write_all(&[OPCODE_ITOB]).unwrap(),
            OpCode::TypeQ => output.write_all(&[OPCODE_TYPEQ]).unwrap(),

            OpCode::PushB(bts) => {
                if bts.len() > 255 {
                    return Err(EncodeError::TooManyBytes);
                }
                output.write_all(&[OPCODE_PUSHB]).unwrap();
                output.write_all(&[bts.len() as u8]).unwrap();
                output.write_all(bts).unwrap();
            }
            OpCode::PushI(i) => {
                output.write_all(&[OPCODE_PUSHI]).unwrap();
                output.write_all(&i.to_be_bytes()).unwrap();
            }
            OpCode::PushIC(i) => {
                output.write_all(&[OPCODE_PUSHIC]).unwrap();
                let bytes_repr = i.to_be_bytes();
                let leading_zeros = bytes_repr.iter().take_while(|i| **i == 0).count();
                output.write_all(&[32 - (leading_zeros as u8)]).unwrap();
                output
                    .write_all(&bytes_repr[leading_zeros as usize..])
                    .unwrap();
            }
            OpCode::Dup => output.write_all(&[OPCODE_DUP]).unwrap(),
            OpCode::Oflo => output.write_all(&[OPCODE_OFLO]).unwrap(),
            OpCode::Cloflo => output.write_all(&[OPCODE_CLOFLO]).unwrap(),
        };
        Ok(output)
    }

    /// Decodes an opcode from an input.
    pub fn decode<T: std::io::Read>(input: &mut T) -> Result<Self, DecodeError> {
        let u16arg = |input: &mut T| {
            let mut buffer: [u8; 2] = [0; 2];
            input.read_exact(&mut buffer)?;
            Ok::<_, DecodeError>(u16::from_be_bytes(buffer))
        };

        let u8arg = |input: &mut T| {
            let mut buffer: [u8; 1] = [0; 1];
            input.read_exact(&mut buffer)?;
            Ok::<_, DecodeError>(u8::from_be_bytes(buffer))
        };

        match read_byte(input)? {
            OPCODE_NOOP => Ok(OpCode::Noop),
            // arithmetic
            OPCODE_ADD => Ok(OpCode::Add),
            OPCODE_SUB => Ok(OpCode::Sub),
            OPCODE_MUL => Ok(OpCode::Mul),
            OPCODE_DIV => Ok(OpCode::Div),
            OPCODE_REM => Ok(OpCode::Rem),
            OPCODE_EXP => Ok(OpCode::Exp(u8arg(input)?)),
            // logic
            OPCODE_AND => Ok(OpCode::And),
            OPCODE_OR => Ok(OpCode::Or),
            OPCODE_XOR => Ok(OpCode::Xor),
            OPCODE_NOT => Ok(OpCode::Not),
            OPCODE_EQL => Ok(OpCode::Eql),
            OPCODE_LT => Ok(OpCode::Lt),
            OPCODE_GT => Ok(OpCode::Gt),
            OPCODE_SHL => Ok(OpCode::Shl),
            OPCODE_SHR => Ok(OpCode::Shr),
            // cryptography
            OPCODE_HASH => Ok(OpCode::Hash(u16arg(input)?)),
            //0x31 => Ok(OpCode::SIGE),
            OPCODE_SIGEOK => Ok(OpCode::SigEOk(u16arg(input)?)),
            // storage
            OPCODE_LOAD => Ok(OpCode::Load),
            OPCODE_STORE => Ok(OpCode::Store),
            OPCODE_LOADIMM => Ok(OpCode::LoadImm(u16arg(input)?)),
            OPCODE_STOREIMM => Ok(OpCode::StoreImm(u16arg(input)?)),
            // vectors
            OPCODE_VREF => Ok(OpCode::VRef),
            OPCODE_VAPPEND => Ok(OpCode::VAppend),
            OPCODE_VEMPTY => Ok(OpCode::VEmpty),
            OPCODE_VLENGTH => Ok(OpCode::VLength),
            OPCODE_VSLICE => Ok(OpCode::VSlice),
            OPCODE_VSET => Ok(OpCode::VSet),
            OPCODE_VPUSH => Ok(OpCode::VPush),
            OPCODE_VCONS => Ok(OpCode::VCons),
            // bytes
            OPCODE_BREF => Ok(OpCode::BRef),
            OPCODE_BAPPEND => Ok(OpCode::BAppend),
            OPCODE_BEMPTY => Ok(OpCode::BEmpty),
            OPCODE_BLENGTH => Ok(OpCode::BLength),
            OPCODE_BSLICE => Ok(OpCode::BSlice),
            OPCODE_BSET => Ok(OpCode::BSet),
            OPCODE_BPUSH => Ok(OpCode::BPush),
            OPCODE_BCONS => Ok(OpCode::BCons),
            // control flow
            OPCODE_TYPEQ => Ok(OpCode::TypeQ),
            OPCODE_JMP => Ok(OpCode::Jmp(u16arg(input)?)),
            OPCODE_BEZ => Ok(OpCode::Bez(u16arg(input)?)),
            OPCODE_BNZ => Ok(OpCode::Bnz(u16arg(input)?)),
            OPCODE_LOOP => {
                let iterations = u16arg(input)?;
                let count = u16arg(input)?;
                Ok(OpCode::Loop(iterations, count))
            }
            OPCODE_ITOB => Ok(OpCode::ItoB),
            OPCODE_BTOI => Ok(OpCode::BtoI),
            // literals
            OPCODE_PUSHB => {
                let strlen = read_byte(input)?;
                let mut blit = vec![0u8; strlen as usize];
                input.read_exact(&mut blit)?;
                Ok(OpCode::PushB(blit))
            }
            OPCODE_PUSHI => {
                let mut buf = [0; 32];
                input.read_exact(&mut buf)?;
                Ok(OpCode::PushI(U256::from_be_bytes(buf)))
            }
            OPCODE_PUSHIC => {
                let mut buf = [0; 32];
                let nonzero_len = read_byte(input)?;
                if nonzero_len > 32 {
                    return Err(DecodeError::InvalidVarint);
                }
                let mut blit = &mut buf[..nonzero_len as usize];
                input.read_exact(&mut blit)?;
                if blit.len() > 32 {
                    return Err(DecodeError::InvalidVarint);
                }
                blit.reverse();
                let integ = U256::from_le_bytes(buf);
                if 32 - (integ.leading_zeros() / 8) != nonzero_len as u32 {
                    return Err(DecodeError::InvalidVarint);
                }
                Ok(OpCode::PushIC(integ))
            }
            OPCODE_DUP => Ok(OpCode::Dup),
            OPCODE_OFLO => Ok(OpCode::Oflo),
            OPCODE_CLOFLO => Ok(OpCode::Cloflo),
            b => Err(DecodeError::InvalidOpcode(b)),
        }
    }
}

/// Computes the weight of a bunch of opcodes.
pub fn opcodes_weight(opcodes: &[OpCode]) -> u128 {
    let (mut sum, mut rest) = opcodes_car_weight(opcodes);
    while !rest.is_empty() {
        let (delta_sum, new_rest) = opcodes_car_weight(rest);
        rest = new_rest;
        sum = sum.saturating_add(delta_sum);
    }
    sum
}

/// Compute the weight of the first bit of opcodes, returning a weight and what remains.
fn opcodes_car_weight(opcodes: &[OpCode]) -> (u128, &[OpCode]) {
    if opcodes.is_empty() {
        return (0, opcodes);
    }
    let (first, rest) = opcodes.split_first().unwrap();
    match first {
        OpCode::Noop => (1, rest),
        // handle loops specially
        OpCode::Loop(iters, body_len) => {
            let mut sum = 0u128;
            let mut rest = rest;

            let range = 0..*body_len;

            range.into_iter().for_each(|_index| {
                let (weight, rem) = opcodes_car_weight(rest);
                sum = sum.saturating_add(weight);
                rest = rem;
            });

            (sum.saturating_mul(*iters as u128).saturating_add(1), rest)
        }
        OpCode::Add => (4, rest),
        OpCode::Sub => (4, rest),
        OpCode::Mul => (6, rest),
        OpCode::Div => (6, rest),
        // We add 1 to k bcs the max is 256 bits and min is 1, so 0=>1, 2^8=>256
        OpCode::Exp(k) => (
            6u128.saturating_add(10u128.saturating_mul(*k as u128 + 1)),
            rest,
        ),
        OpCode::Rem => (6, rest),

        OpCode::And => (4, rest),
        OpCode::Or => (4, rest),
        OpCode::Xor => (4, rest),
        OpCode::Not => (4, rest),
        OpCode::Eql => (4, rest),
        OpCode::Lt => (4, rest),
        OpCode::Gt => (4, rest),
        OpCode::Shl => (4, rest),
        OpCode::Shr => (4, rest),

        OpCode::Hash(n) => (50u128.saturating_add(*n as u128), rest),
        OpCode::SigEOk(n) => (100u128.saturating_add(*n as u128), rest),

        OpCode::Store => (10, rest),
        OpCode::Load => (10, rest),
        OpCode::StoreImm(_) => (4, rest),
        OpCode::LoadImm(_) => (4, rest),

        OpCode::VRef => (10, rest),
        OpCode::VSet => (20, rest),
        OpCode::VAppend => (50, rest),
        OpCode::VSlice => (50, rest),
        OpCode::VLength => (4, rest),
        OpCode::VEmpty => (4, rest),
        OpCode::BEmpty => (4, rest),
        OpCode::BPush => (10, rest),
        OpCode::VPush => (10, rest),
        OpCode::VCons => (10, rest),
        OpCode::BRef => (10, rest),
        OpCode::BAppend => (10, rest),
        OpCode::BLength => (4, rest),
        OpCode::BSlice => (50, rest),
        OpCode::BSet => (20, rest),
        OpCode::BCons => (10, rest),

        OpCode::TypeQ => (4, rest),

        OpCode::ItoB => (50, rest),
        OpCode::BtoI => (50, rest),

        OpCode::Bez(_) => (1, rest),
        OpCode::Bnz(_) => (1, rest),
        OpCode::Jmp(_) => (1, rest),

        OpCode::PushB(_) => (1, rest),
        OpCode::PushI(_) => (1, rest),
        OpCode::PushIC(_) => (1, rest),

        OpCode::Dup => (4, rest),
        OpCode::Oflo => (1, rest),
        OpCode::Cloflo => (1, rest),
    }
}

#[cfg(test)]
#[allow(clippy::bool_assert_comparison)]
mod tests {
    use crate::melvm::opcode::OpCode;
    use crate::melvm::{Covenant, Value};

    use std::collections::HashMap;
    use std::str::FromStr;

    use catvec::CatVec;
    use ethnum::{u256, U256};
    use log::LevelFilter;
    use tmelcrypt::{ed25519_keygen, Ed25519PK, Ed25519SK};

    #[test]
    fn test_noop() {
        let covenant: Covenant =
            Covenant::from_ops(&[OpCode::Noop]).expect("Failed to create a NoOp covenant.");
        assert_eq!(covenant.debug_run_without_transaction(&[]), false)
    }

    #[test]
    fn test_addition() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(1_u8.into()),
            OpCode::PushI(2_u8.into()),
            OpCode::Add,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Add covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(1_u8.into()),
            OpCode::PushI(2_u8.into()),
            OpCode::Add,
            OpCode::PushI(4_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Add covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    fn log_init() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(LevelFilter::Trace)
            .try_init();
    }

    #[test]
    fn test_exponentiate() {
        log_init();
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(256_u32.into()),
            OpCode::PushI(2_u32.into()),
            OpCode::Exp(32),
            OpCode::PushI(0_u8.into()),
            OpCode::Eql,
        ])
        .unwrap();
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(1_u8.into()),
            OpCode::PushI(2_u8.into()),
            OpCode::Add,
            OpCode::PushI(4_u8.into()),
            OpCode::Eql,
        ])
        .unwrap();
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_addition_with_overflow() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(1_u8.into()),
            OpCode::PushI(u256::MAX.into()),
            OpCode::Add,
            OpCode::PushI(0_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Add covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_subtraction() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(1_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Sub,
            OpCode::PushI(2_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Sub covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(1_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Sub,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Sub covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_subtraction_with_wraparound() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(2_u8.into()),
            OpCode::PushI(1_u8.into()),
            OpCode::Sub,
            OpCode::PushI(u256::MAX),
            OpCode::Eql,
        ])
        .expect("Failed to create a Sub covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_multiply() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(2_u8.into()),
            OpCode::Mul,
            OpCode::PushI(6_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Mul covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(2_u8.into()),
            OpCode::Mul,
            OpCode::PushI(7_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Mul covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_multiply_with_overflow() {
        let half_maximum: u256 = u256::MAX / 2;
        let maximum_plus_two: u256 = half_maximum + 2;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(maximum_plus_two.into()),
            OpCode::PushI(2_u128.into()),
            OpCode::Mul,
            OpCode::PushI(2_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Mul covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_divide() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(2_u8.into()),
            OpCode::PushI(6_u8.into()),
            OpCode::Div,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Div covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::Div,
            OpCode::PushI(0_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Div covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_divide_to_zero() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(2_u8.into()),
            OpCode::PushI(1_u8.into()),
            OpCode::Div,
            OpCode::PushI(0_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Div covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_divide_with_decimal() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::Div,
            OpCode::PushI(1_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Div covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_remainder() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(6_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Rem,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Rem covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(6_u8.into()),
            OpCode::PushI(6_u8.into()),
            OpCode::Rem,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Rem covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_remainder_is_zero() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(1_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Rem,
            OpCode::PushI(0_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Rem covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_bitwise_and() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::And,
            OpCode::PushI(1_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a And covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(2_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::And,
            OpCode::PushI(2_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a And covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(2_u8.into()),
            OpCode::PushI(9_u8.into()),
            OpCode::And,
            OpCode::PushI(2_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a And covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_bitwise_or() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::Or,
            OpCode::PushI(7_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Or covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(8_u8.into()),
            OpCode::PushI(2_u8.into()),
            OpCode::Or,
            OpCode::PushI(10_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Or covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(16_u8.into()),
            OpCode::PushI(8_u8.into()),
            OpCode::Or,
            OpCode::PushI(10_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Or covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_bitwise_xor() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::Xor,
            OpCode::PushI(6_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Xor covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(10_u8.into()),
            OpCode::PushI(2_u8.into()),
            OpCode::Xor,
            OpCode::PushI(8_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Xor covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(10_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Xor,
            OpCode::PushI(8_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Xor covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_bitwise_not_with_wraparound() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(0_u8.into()),
            OpCode::Not,
            OpCode::PushI(u256::MAX.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Not covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_equality() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Eql covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Eql covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_less_than() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Lt,
        ])
        .expect("Failed to create a Lt covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Lt,
        ])
        .expect("Failed to create a Lt covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::Lt,
        ])
        .expect("Failed to create a Lt covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_greater_than() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::Gt,
        ])
        .expect("Failed to create a Gt covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Lt,
        ])
        .expect("Failed to create a Gt covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Lt,
        ])
        .expect("Failed to create a Gt covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(7_u8.into()),
            OpCode::Lt,
        ])
        .expect("Failed to create a Gt covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_bit_shift_left() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(1_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Shl,
            OpCode::PushI(6_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Shl covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let half_max: u256 = u256::MAX / 2;
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(1_u8.into()),
            OpCode::PushI(half_max.into()),
            OpCode::Shl,
            OpCode::PushI((u256::MAX - 1).into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Shl covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let half_max: u256 = u256::MAX / 2;
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(half_max.into()),
            OpCode::Shl,
            OpCode::PushI((u256::MAX - 1).into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Shl covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_bit_shift_right() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(1_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Shr,
            OpCode::PushI(1_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Shr covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(1_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::Shr,
            OpCode::PushI(2_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Shr covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(2_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::Shr,
            OpCode::PushI(2_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Shr covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_hash() {
        let byte_vector: Vec<u8> = vec![3];

        let number_of_bytes_to_hash: u16 = 1;

        let hash: tmelcrypt::HashVal =
            tmelcrypt::hash_single(&byte_vector[..number_of_bytes_to_hash as usize]);

        let hash_vector: Vec<u8> = hash.to_vec();

        dbg!("Hash Vector: {}", &hash_vector);

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushB(byte_vector),
            OpCode::Hash(number_of_bytes_to_hash),
            OpCode::BtoI,
            OpCode::PushB(hash_vector),
            OpCode::BtoI,
            OpCode::Eql,
        ])
        .expect("Failed to create a Hash covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_sigeok() {
        let (public_key, secret_key): (Ed25519PK, Ed25519SK) = ed25519_keygen();

        let message_byte_vector: Vec<u8> = vec![3];

        let signature: Vec<u8> = secret_key.sign(&message_byte_vector);

        let number_of_bytes_to_hash: u16 = 1;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushB(signature),
            OpCode::PushB(public_key.0.to_vec()),
            OpCode::PushB(message_byte_vector),
            OpCode::SigEOk(number_of_bytes_to_hash),
        ])
        .expect("Failed to create a SigEOk covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_heap_store_and_load() {
        let address: u8 = 0x1;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(address.into()),
            OpCode::Store,
            OpCode::PushI(address.into()),
            OpCode::Load,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Store/Load covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_heap_storeimm_and_loadimm() {
        let index: u8 = 1;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::StoreImm(index.into()),
            OpCode::LoadImm(index.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a StoreImm/LoadImm covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_verify_an_index_of_a_vm_vector() {
        let index: u8 = 0;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(index.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::VEmpty,
            OpCode::VPush,
            OpCode::VRef,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a VEmpty/VPush/VRef covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_overwrite_an_index_of_a_vm_vector() {
        let new_value: u8 = 3;
        let index: u8 = 1;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(index.into()),
            OpCode::PushI(new_value.into()),
            OpCode::PushI(index.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::VEmpty,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VSet,
            OpCode::VRef,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a VEmpty/VPush/VSet/VRef covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_append_one_vm_vector_to_another() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(8_u8.into()),
            OpCode::PushI(7_u8.into()),
            OpCode::PushI(6_u8.into()),
            OpCode::VEmpty,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::VEmpty,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VAppend,
            OpCode::VLength,
            OpCode::PushI(6_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a VEmpty/VPush/VAppend/VLength covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[OpCode::PushI(3_u8.into()), OpCode::VLength])
            .expect("Failed to create a VLength covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_insert_at_the_beginning_of_a_vm_vector() {
        let index: u8 = 0;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(index.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::VEmpty,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::PushI(3_u8.into()),
            OpCode::VCons,
            OpCode::VRef,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a VEmpty/VPush/VCons/VRef covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_verify_an_index_of_a_vm_slice() {
        let index: u8 = 0;
        let beginning: u8 = 1;
        let end: u8 = 3;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(index.into()),
            OpCode::PushI(end.into()),
            OpCode::PushI(beginning.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(2_u8.into()),
            OpCode::PushI(1_u8.into()),
            OpCode::VEmpty,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VSlice,
            OpCode::VRef,
            OpCode::PushI(2_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a VEmpty/VPush/VSlice/VRef covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_verify_the_length_of_a_vm_slice() {
        let length: u8 = 2;
        let beginning: u8 = 1;
        let end: u8 = 3;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(end.into()),
            OpCode::PushI(beginning.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(2_u8.into()),
            OpCode::PushI(1_u8.into()),
            OpCode::VEmpty,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VSlice,
            OpCode::VLength,
            OpCode::PushI(length.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a VEmpty/VPush/VSlice/VLength covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_verify_empty_vector_with_out_of_bounds_vm_slice() {
        let length: u8 = 0;
        let beginning: u8 = 1;
        let end: u8 = 5;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(end.into()),
            OpCode::PushI(beginning.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(2_u8.into()),
            OpCode::PushI(1_u8.into()),
            OpCode::VEmpty,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VPush,
            OpCode::VSlice,
            OpCode::VLength,
            OpCode::PushI(length.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a VEmpty/VPush/VSlice/VLength covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_verify_an_index_of_a_byte_vector() {
        let index: u8 = 0;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(index.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::BEmpty,
            OpCode::BPush,
            OpCode::BRef,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a BEmpty/BPush/BRef covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_overwrite_an_index_of_a_byte_vector() {
        let new_value: u8 = 3;
        let index: u8 = 1;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(index.into()),
            OpCode::PushI(new_value.into()),
            OpCode::PushI(index.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::BEmpty,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BSet,
            OpCode::BRef,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a BEmpty/BPush/BSet/BRef covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_bref() {
        let index: u8 = 0;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(index.into()),
            OpCode::PushB(vec![3, 4, 5]),
            OpCode::BRef,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a BRef covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let index: u8 = 0;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(index.into()),
            OpCode::PushB(vec![3, 4, 5]),
            OpCode::BRef,
            OpCode::PushI(5_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a BRef covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_bempty_bpush_and_bref() {
        let index: u8 = 0;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(index.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::BEmpty,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BRef,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a BEmpty/BPush/BRef covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_insert_at_the_beginning_of_a_byte_vector() {
        let index: u8 = 0;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(index.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::BEmpty,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::PushI(3_u8.into()),
            OpCode::BCons,
            OpCode::BRef,
            OpCode::PushI(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a BEmpty/BPush/BCons/BRef covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_append_one_byte_vector_to_another() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(8_u8.into()),
            OpCode::PushI(7_u8.into()),
            OpCode::PushI(6_u8.into()),
            OpCode::BEmpty,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::BEmpty,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BAppend,
            OpCode::BLength,
            OpCode::PushI(6_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a BEmpty/BPush/BAppend/BLength covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);

        let covenant: Covenant = Covenant::from_ops(&[OpCode::PushI(3_u8.into()), OpCode::BLength])
            .expect("Failed to create a BLength covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_verify_an_index_of_a_byte_slice() {
        let index: u8 = 0;
        let beginning: u8 = 1;
        let end: u8 = 3;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(index.into()),
            OpCode::PushI(end.into()),
            OpCode::PushI(beginning.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(2_u8.into()),
            OpCode::PushI(1_u8.into()),
            OpCode::BEmpty,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BSlice,
            OpCode::BRef,
            OpCode::PushI(2_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a BEmpty/BPush/BSlice/BRef covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_verify_the_length_of_a_byte_slice() {
        let length: u8 = 2;
        let beginning: u8 = 1;
        let end: u8 = 3;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(end.into()),
            OpCode::PushI(beginning.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(2_u8.into()),
            OpCode::PushI(1_u8.into()),
            OpCode::BEmpty,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BSlice,
            OpCode::BLength,
            OpCode::PushI(length.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a BEmpty/BPush/BSlice/BLength covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_verify_empty_vector_with_out_of_bounds_byte_slice() {
        let length: u8 = 0;
        let beginning: u8 = 1;
        let end: u8 = 5;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(end.into()),
            OpCode::PushI(beginning.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(4_u8.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(2_u8.into()),
            OpCode::PushI(1_u8.into()),
            OpCode::BEmpty,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BPush,
            OpCode::BSlice,
            OpCode::BLength,
            OpCode::PushI(length.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a BEmpty/BPush/BSlice/BLength covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_skipping_an_operation_with_bez() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(0_u8.into()),
            OpCode::Bez(1),
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Bezh covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_not_skipping_an_operation_with_bez() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(5_u8.into()),
            OpCode::Bez(1),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Bez covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_skipping_an_operation_with_bnz() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(1_u8.into()),
            OpCode::Bnz(1),
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Bnz covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_not_skipping_an_operation_with_bnz() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(0_u8.into()),
            OpCode::Bnz(1),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Bnz covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_skipping_an_operation_with_jmp() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::Jmp(1),
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Jmp covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_loop() {
        // This will loop the PushI(3) opcode twice, and then run PushI(5).
        // Comparing equality will fail because it is comparing 5 and 3.
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::Loop(2, 1),
            OpCode::PushI(3_u8.into()),
            OpCode::PushI(5_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a Loop covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_loop_inputs_being_not_positive() {
        let covenant: Covenant =
            Covenant::from_ops(&[OpCode::Loop(0, 3)]).expect("Failed to create a Loop covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);

        let covenant: Covenant =
            Covenant::from_ops(&[OpCode::Loop(3, 0)]).expect("Failed to create a Loop covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);

        let covenant: Covenant =
            Covenant::from_ops(&[OpCode::Loop(0, 0)]).expect("Failed to create a Loop covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_convert_bytes_to_integer() {
        let array: [u8; 32] = [3; 32];

        let number: u256 = U256::from_str(
            "1362259873380190534394952764808093033567882172536947812228912753034272113411",
        )
        .expect("could not create a U256 from a str.");

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushB(array.to_vec()),
            OpCode::BtoI,
            OpCode::PushI(number.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a BtoI covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_convert_bytes_to_integer_failing() {
        let array: [u8; 4] = [3; 4];

        let covenant: Covenant = Covenant::from_ops(&[OpCode::PushB(array.to_vec()), OpCode::BtoI])
            .expect("Failed to create a BtoI covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }

    #[test]
    fn test_convert_integer_to_bytes() {
        let array: [u8; 32] = [3; 32];

        let catvec_array: CatVec<u8, 256_usize> = CatVec::from(array);

        let number: u256 = U256::from_str(
            "1362259873380190534394952764808093033567882172536947812228912753034272113411",
        )
        .expect("could not create a U256 from a str.");

        let covenant: Covenant = Covenant::from_ops(&[OpCode::PushI(number.into()), OpCode::ItoB])
            .expect("Failed to create a ItoB covenant.");
        let (stack, _heap): (Vec<Value>, HashMap<u16, Value>) = covenant
            .debug_run_outputting_stack_and_heap(&[])
            .expect("Covenant returned a None value.");

        dbg!("{}", &stack);

        let byte_vector: CatVec<u8, 256_usize> = stack[0]
            .clone()
            .into_bytes()
            .expect("Could not convert stack index into bytes.");

        assert_eq!(catvec_array, byte_vector);
    }

    #[test]
    fn test_pushic() {
        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(3_u8.into()),
            OpCode::PushIC(3_u8.into()),
            OpCode::Eql,
        ])
        .expect("Failed to create a PushIC covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_typeq_integer() {
        let integer_code: u8 = 0;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(integer_code.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::TypeQ,
            OpCode::Eql,
        ])
        .expect("Failed to create a TypeQ covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_typeq_byte_vector() {
        let byte_vector_code: u8 = 1;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(byte_vector_code.into()),
            OpCode::PushB(vec![3, 4, 5]),
            OpCode::TypeQ,
            OpCode::Eql,
        ])
        .expect("Failed to create a TypeQ covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_typeq_vector() {
        let byte_vector_code: u8 = 2;

        let covenant: Covenant = Covenant::from_ops(&[
            OpCode::PushI(byte_vector_code.into()),
            OpCode::PushI(3_u8.into()),
            OpCode::VEmpty,
            OpCode::VPush,
            OpCode::TypeQ,
            OpCode::Eql,
        ])
        .expect("Failed to create a TypeQ covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_dup() {
        let covenant: Covenant =
            Covenant::from_ops(&[OpCode::PushI(3_u8.into()), OpCode::Dup, OpCode::Eql])
                .expect("Failed to create a Dup covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_oflo() {
        let covenant: Covenant =
            Covenant::from_ops(&[
                OpCode::PushI(U256::MAX),
                OpCode::PushI(U256::ONE),
                OpCode::Add,
                OpCode::Oflo])
                .expect("Failed to create an oflo covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);
        assert_eq!(output, true);

        let covenant: Covenant =
            Covenant::from_ops(&[
                OpCode::PushI(U256::MAX),
                OpCode::PushI(U256::ONE),
                OpCode::Add,
                OpCode::PushI(U256::ONE),
                OpCode::Add,
                OpCode::Oflo])
                .expect("Failed to create an oflo covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, true);
    }

    #[test]
    fn test_cloflo() {
        let covenant: Covenant =
            Covenant::from_ops(&[
                OpCode::PushI(U256::MAX),
                OpCode::PushI(U256::ONE),
                OpCode::Add,
                OpCode::PushI(U256::ONE),
                OpCode::Add,
                OpCode::Cloflo,
                OpCode::Oflo,
            ])
                .expect("Failed to create an oflo covenant.");
        let output: bool = covenant.debug_run_without_transaction(&[]);

        assert_eq!(output, false);
    }
}
