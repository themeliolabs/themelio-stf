use std::collections::HashMap;

use catvec::CatVec;
use ethnum::U256;
use tap::Tap;
use themelio_structs::{CoinData, CoinDataHeight, CoinID, Transaction};

use super::{
    consts::{
        HADDR_LAST_HEADER, HADDR_PARENT_ADDITIONAL_DATA, HADDR_PARENT_DENOM, HADDR_PARENT_HEIGHT,
        HADDR_PARENT_INDEX, HADDR_PARENT_TXHASH, HADDR_PARENT_VALUE, HADDR_SELF_HASH,
        HADDR_SPENDER_INDEX, HADDR_SPENDER_TX, HADDR_SPENDER_TXHASH,
    },
    opcode::OpCode,
    CovenantEnv, Value,
};

/// A pointer to the currently executing instruction.
type ProgramCounter = usize;

/// Internal tracking of state during a loop in [Executor].
struct LoopState {
    /// Pointer to first op in loop
    begin: ProgramCounter,
    /// Pointer to last op in loop (inclusive)
    end: ProgramCounter,
    /// Total number of iterations
    iterations_left: u16,
}

/// An object that executes MelVM code.
pub struct Executor {
    pub stack: Vec<Value>,
    pub heap: HashMap<u16, Value>,
    /// Overflow flag on an op
    overflow: bool,
    instrs: Vec<OpCode>,
    /// Program counter
    pc: ProgramCounter,
    /// Marks the (begin, end) of the loop if currently in one
    loop_state: Vec<LoopState>,
}

impl Executor {
    /// Creates a new Executor, with the given initial heap.
    pub fn new(instrs: Vec<OpCode>, heap_init: HashMap<u16, Value>) -> Self {
        Executor {
            stack: Vec::new(),
            heap: heap_init,
            overflow: false,
            instrs,
            pc: 0,
            loop_state: vec![],
        }
    }

    /// Creates a new Executor, with a heap populated with the given transaction and environment.
    pub fn new_from_env(instrs: Vec<OpCode>, tx: Transaction, env: Option<CovenantEnv>) -> Self {
        let mut hm = HashMap::new();
        hm.insert(HADDR_SPENDER_TXHASH, Value::from_bytes(&tx.hash_nosigs().0));
        let tx_val = Value::from(tx);
        hm.insert(HADDR_SPENDER_TX, tx_val);
        if let Some(env) = env {
            let CoinID { txhash, index } = &env.parent_coinid;

            hm.insert(HADDR_PARENT_TXHASH, txhash.0.into());
            hm.insert(HADDR_PARENT_INDEX, Value::Int(U256::from(*index)));

            let CoinDataHeight {
                coin_data:
                    CoinData {
                        covhash,
                        value,
                        denom,
                        additional_data,
                    },
                height,
            } = &env.parent_cdh;

            hm.insert(HADDR_SELF_HASH, covhash.0.into());
            hm.insert(HADDR_PARENT_VALUE, (value.0).into());
            hm.insert(HADDR_PARENT_DENOM, (*denom).into());
            hm.insert(HADDR_PARENT_ADDITIONAL_DATA, additional_data.clone().into());
            hm.insert(HADDR_PARENT_HEIGHT, height.0.into());
            hm.insert(HADDR_LAST_HEADER, Value::from(*env.last_header));
            hm.insert(HADDR_SPENDER_INDEX, Value::from(env.spender_index as u64));
        }

        Executor::new(instrs, hm)
    }
    fn do_triop(&mut self, op: impl Fn(Value, Value, Value) -> Option<Value>) -> Option<()> {
        let stack = &mut self.stack;
        let x = stack.pop()?;
        let y = stack.pop()?;
        let z = stack.pop()?;
        stack.push(op(x, y, z)?);
        Some(())
    }
    fn do_binop(&mut self, op: impl Fn(Value, Value) -> Option<(Value, bool)>) -> Option<()> {
        let stack = &mut self.stack;
        let x = stack.pop()?;
        let y = stack.pop()?;
        let (val, oflo) = op(x, y)?;
        stack.push(val);
        self.overflow |= oflo;

        // eprintln!("stack at {}", stack.len());
        Some(())
    }
    fn do_monop(&mut self, op: impl Fn(Value) -> Option<Value>) -> Option<()> {
        let stack = &mut self.stack;
        let x = stack.pop()?;
        stack.push(op(x)?);
        Some(())
    }

    /// Obtains the current program counter.
    pub fn pc(&self) -> ProgramCounter {
        self.pc
    }

    /// Update program pointer state (for loops etc)
    fn update_pc_state(&mut self) {
        while let Some(mut state) = self.loop_state.pop() {
            // If done with body of loop
            if self.pc > state.end {
                // But not finished with all iterations, and did not jump outside the loop
                if state.iterations_left > 0 && self.pc.saturating_sub(state.end) == 1 {
                    log::trace!("{} iterations left", state.iterations_left);
                    // loop again
                    state.iterations_left -= 1;
                    self.pc = state.begin;
                    self.loop_state.push(state);
                    break;
                }
            } else {
                // If not done with loop body, resume
                self.loop_state.push(state);
                break;
            }
        }
    }

    /// Execute to the end
    pub fn run_to_end(&mut self) -> bool {
        while self.pc < self.instrs.len() {
            if self.step().is_none() {
                return false;
            }
        }

        self.stack.pop().map(|f| f.into_bool()).unwrap_or_default()
    }

    /// Execute to the end, without popping.
    pub fn run_to_end_preserve_stack(&mut self) -> bool {
        while self.pc < self.instrs.len() {
            if self.step().is_none() {
                return false;
            }
        }
        self.stack
            .last()
            .map(|f| f.clone().into_bool())
            .unwrap_or_default()
    }

    /// Checks whether or not the execution has come to an end.
    pub fn at_end(&self) -> bool {
        self.pc == self.instrs.len()
    }

    /// Execute an instruction, modifying state and program counter.
    pub fn step(&mut self) -> Option<()> {
        let mut inner = || {
            let op = self.instrs.get(self.pc)?.clone();
            // eprintln!("OPS: {:?}", self.instrs);
            // eprintln!("PC:  {}", self.pc);
            // eprintln!("OP:  {:?}", op);
            // eprintln!("STK: {:?}", self.stack);
            // eprintln!();
            self.pc += 1;
            // eprintln!("running {:?}", op);
            match op {
                OpCode::Noop => {
                    log::trace!("NoOp");
                }
                // arithmetic
                OpCode::Add => self.do_binop(|x, y| {
                    log::trace!("Addition, First: {:?}", &x);
                    log::trace!("Addition, Second: {:?}", &y);

                    let (val, oflo) = x.into_int()?.overflowing_add(y.into_int()?);
                    Some((Value::Int(val), oflo))
                })?,
                OpCode::Sub => self.do_binop(|x, y| {
                    log::trace!("Subtraction, First: {:?}", &x);
                    log::trace!("Subtraction, Second: {:?}", &y);

                    let (val, oflo) = x.into_int()?.overflowing_sub(y.into_int()?);
                    Some((Value::Int(val), oflo))
                })?,
                OpCode::Mul => self.do_binop(|x, y| {
                    log::trace!("Multiplication, First: {:?}", &x);
                    log::trace!("Multiplication, Second: {:?}", &y);

                    let (val, oflo) = x.into_int()?.overflowing_mul(y.into_int()?);
                    Some((Value::Int(val), oflo))
                })?,
                OpCode::Div => self
                    .do_binop(|x, y| {
                        log::trace!("Division, First: {:?}", &x);
                        log::trace!("Division, Second: {:?}", &y);

                        Some((Value::Int(x.into_int()?.checked_div(y.into_int()?)?), false))
                    })?,
                OpCode::Exp(k) => self
                    .do_binop(|b, e| {
                        log::trace!("Exponentiation, Base: {:?}", &b);
                        log::trace!("Exponentiation, Exponent: {:?}", &e);

                        let mut e = e.into_int()?;
                        let mut b = b.into_int()?;

                        let mut res: U256 = U256::ONE;
                        let mut k: u16 = (k as u16)+1;
                        let mut oflo = false;

                        // Exponentiate by squaring
                        while e > U256::ZERO {
                            // If k runs out then exponent has more bits than claimed in the
                            // bytecode, this is a failure in the vm.
                            k = k.checked_sub(1)?;

                            if e & U256::ONE == U256::ONE {
                                let (r, o) = res.overflowing_mul(b);
                                res = r;
                                oflo |= o;
                            }
                            let (_b, o) = b.overflowing_mul(b);
                            oflo |= o;
                            b = _b;

                            e >>= 1i16;
                        }

                        Some((Value::Int(res), oflo))
                    })?,
                OpCode::Rem => self
                    .do_binop(|x, y| {
                        log::trace!("Remainder, First: {:?}", &x);
                        log::trace!("Remainder, Second: {:?}", &y);

                        Some((Value::Int(x.into_int()?.checked_rem(y.into_int()?)?), false))
                    })?,
                // logic
                OpCode::And => {
                    self.do_binop(|x, y| {
                        Some((Value::Int(x.into_int()? & y.into_int()?), false))
                    })?
                }
                OpCode::Or => {
                    self.do_binop(|x, y| {
                        Some((Value::Int(x.into_int()? | y.into_int()?), false))
                    })?
                }
                OpCode::Xor => {
                    self.do_binop(|x, y| {
                        Some((Value::Int(x.into_int()? ^ y.into_int()?), false))
                    })?
                }
                OpCode::Not => self.do_monop(|x| {
                    Some(Value::Int(!x.into_int()?))
                })?,
                OpCode::Eql => self.do_binop(|x, y| match (x, y) {
                    (Value::Int(x), Value::Int(y)) => {
                        log::trace!("Equality, First: {}", &x);
                        log::trace!("Equality, Second: {}", &y);
                        if x == y {
                            Some((Value::Int(1u32.into()), false))
                        } else {
                            Some((Value::Int(0u32.into()), false))
                        }
                    }
                    _ => None,
                })?,
                OpCode::Lt => self.do_binop(|x, y| {
                    log::trace!("Less than, First: {:?}", &x);
                    log::trace!("Less than, Second: {:?}", &y);

                    let x = x.into_int()?;
                    let y = y.into_int()?;
                    if x < y {
                        Some((Value::Int(1u32.into()), false))
                    } else {
                        Some((Value::Int(0u32.into()), false))
                    }
                })?,
                OpCode::Gt => self.do_binop(|x, y| {
                    log::trace!("Greater than, First: {:?}", &x);
                    log::trace!("Greater than, Second: {:?}", &y);

                    let x = x.into_int()?;
                    let y = y.into_int()?;
                    if x > y {
                        Some((Value::Int(1u32.into()), false))
                    } else {
                        Some((Value::Int(0u32.into()), false))
                    }
                })?,
                OpCode::Shl => self.do_binop(|x, offset| {
                    let x = x.into_int()?;
                    let offset = offset.into_int()?;

                    Some((Value::Int(x.wrapping_shl(offset.as_u32())), false))
                })?,
                OpCode::Shr => self.do_binop(|x, offset| {
                    let x = x.into_int()?;
                    let offset = offset.into_int()?;

                    Some((Value::Int(x.wrapping_shr(offset.as_u32())), false))
                })?,
                // cryptography
                OpCode::Hash(n) => self.do_monop(|to_hash| {
                    let bytes: CatVec<u8, 256> = to_hash.into_bytes()?;

                    if bytes.len() > n as usize {
                        return None;
                    }

                    let byte_vector: Vec<u8> = bytes.into();
                    let hash: tmelcrypt::HashVal = tmelcrypt::hash_single(&byte_vector);

                    log::trace!("Hash: {:?}", &hash.0);

                    Some(Value::from_bytes(&hash.0))
                })?,
                OpCode::SigEOk(n) => self.do_triop(|message, public_key, signature| {
                    //println!("SIGEOK({:?}, {:?}, {:?})", message, public_key, signature);
                    let public_key_bytes: CatVec<u8, 256> = public_key.into_bytes()?;

                    if public_key_bytes.len() > 32 {
                        return Some(Value::from_bool(false));
                    }

                    let public_key_byte_vector: Vec<u8> = public_key_bytes.into();
                    let public_key: tmelcrypt::Ed25519PK = tmelcrypt::Ed25519PK::from_bytes(&public_key_byte_vector)?;
                    let message_bytes: CatVec<u8, 256> = message.into_bytes()?;

                    if message_bytes.len() > n as usize {
                        return None;
                    }

                    let message_byte_vector: Vec<u8> = message_bytes.into();
                    let signature_bytes: CatVec<u8, 256> = signature.into_bytes()?;

                    if signature_bytes.len() > 64 {
                        return Some(Value::from_bool(false));
                    }

                    let signature_byte_vector: Vec<u8> = signature_bytes.into();

                    Some(Value::from_bool(public_key.verify(&message_byte_vector, &signature_byte_vector)))
                })?,
                // storage access
                OpCode::Store => {
                    let address: u16 = self.stack.pop()?.into_u16()?;
                    let value: Value = self.stack.pop()?;

                    log::trace!("Storing {:?} at address: {:?} on the heap.", &value, &address);

                    self.heap.insert(address, value);
                }
                OpCode::Load => {
                    let address: u16 = self.stack.pop()?.into_u16()?;
                    let res: Value = self.heap.get(&address)?.clone();

                    log::trace!("Loading {:?} from address: {:?} from the heap.", &res, &address);

                    self.stack.push(res)
                }
                OpCode::StoreImm(idx) => {
                    let value: Value = self.stack.pop()?;

                    log::trace!("Storing {:?} at index {:?} immutably on the heap.", &value, &idx);

                    self.heap.insert(idx, value);
                }
                OpCode::LoadImm(idx) => {
                    let res = self.heap.get(&idx)?.clone();

                    log::trace!("Loading {:?} from index {:?} immutably from the heap.", &res, &idx);

                    self.stack.push(res)
                }
                // vector operations
                OpCode::VRef => self.do_binop(|vec, idx| {
                    let idx: usize = idx.into_u16()? as usize;

                    log::trace!("Loading index {:?} from VM vector containing {:?} onto the stack.", &idx, &vec);

                    Some((vec.into_vector()?.get(idx)?.clone(), false))
                })?,
                OpCode::VSet => self.do_triop(|vec, idx, value| {
                    let idx: usize = idx.into_u16()? as usize;
                    let mut vec: CatVec<Value, 32> = vec.into_vector()?;

                    log::trace!("Overwriting index {:?} of a VM vector containing {:?} with {:?}", &idx, &vec, &value);

                    *vec.get_mut(idx)? = value;

                    Some(Value::Vector(vec))
                })?,
                OpCode::VAppend => self.do_binop(|v1, v2| {
                    let mut v1 = v1.into_vector()?;
                    let v2 = v2.into_vector()?;

                    log::trace!("Appending a vector that contains {:?} to a vector that contains {:?}", &v2, &v1);

                    v1.append(v2);

                    Some((Value::Vector(v1), false))
                })?,
                OpCode::VSlice => self.do_triop(|vec, beginning_value, end_value| {
                    let beginning: usize = beginning_value.into_u16()? as usize;
                    let end: usize = end_value.into_u16()? as usize;

                    match vec {
                        Value::Vector(vec) => {
                            let is_end_greater_or_equal_to_vector_length: bool = end >= vec.len();
                            let is_end_less_than_or_equal_to_beginning: bool = end <= beginning;

                            if is_end_greater_or_equal_to_vector_length || is_end_less_than_or_equal_to_beginning {
                                log::trace!("Tried to create a VM slice with invalid bounds. Returning an empty VM vector.");

                                Some(Value::Vector(Default::default()))
                            } else {
                                log::trace!("Returning a slice from {:?} to {:?} from the VM vector containing: {:?}", beginning, end, &vec);

                                Some(Value::Vector(vec.tap_mut(|vec| vec.slice_into(beginning..end))))
                            }
                        }
                        _ => {
                            log::trace!("Tried to call VSlice on something that was not a VM vector (Value::Vector).");

                            None
                        },
                    }
                })?,
                OpCode::VLength => self.do_monop(|vec| match vec {
                    Value::Vector(vec) => {
                        let length: usize = vec.len();

                        log::trace!("VM vector is of length: {}", length);

                        Some(Value::Int(U256::from(length as u64)))
                    },
                    _ => {
                        log::trace!("Tried to call VLength on something that was not a VM vector (Value::Vector).");

                        None
                    },
                })?,
                OpCode::VEmpty => {
                    log::trace!("Creating a new empty vector on the stack.");

                    self.stack.push(Value::Vector(Default::default()))
                },
                OpCode::VPush => self.do_binop(|vec, item| {
                    let mut vec: CatVec<Value, 32> = vec.into_vector()?;

                    log::trace!("Pushing: {:?} into a VM vector that contains: {:?}.", &item, &vec);

                    vec.push_back(item);

                    Some((Value::Vector(vec), false))
                })?,
                OpCode::VCons => self.do_binop(|item, vec| {
                    let mut vec: CatVec<Value, 32> = vec.into_vector()?;

                    log::trace!("Inserting: {:?} at index 0 of a VM vector that contains: {:?}", &item, &vec);

                    vec.insert(0, item);

                    Some((Value::Vector(vec), false))
                })?,
                // bit stuff
                OpCode::BEmpty => {
                    log::trace!("Creating a new empty byte vector on the stack.");

                    self.stack.push(Value::Bytes(Default::default()))
                },
                OpCode::BPush => self.do_binop(|vec, val| {
                    let mut vec: CatVec<u8, 256> = vec.into_bytes()?;
                    let val: U256 = val.into_int()?;

                    log::trace!("Pushing: {} into a byte vector containing: {:?}", &val, &vec);

                    vec.push_back(*val.low() as u8);

                    Some((Value::Bytes(vec), false))
                })?,
                OpCode::BCons => self.do_binop(|item, vec| {
                    let mut vec: CatVec<u8, 256> = vec.into_bytes()?;

                    log::trace!("Inserting: {:?} at index 0 of a byte vector that contains: {:?}", &item, &vec);

                    vec.insert(0, item.into_truncated_u8()?);

                    Some((Value::Bytes(vec), false))
                })?,
                OpCode::BRef => self.do_binop(|vec, idx| {
                    let idx: usize = idx.into_u16()? as usize;

                    log::trace!("Loading index {:?} from a stack byte vector containing {:?} onto the stack.", &idx, &vec);

                    Some((Value::Int(vec.into_bytes()?.get(idx).copied()?.into()), false))
                })?,
                OpCode::BSet => self.do_triop(|vec, idx, value| {
                    let idx: usize = idx.into_u16()? as usize;
                    let mut vec: CatVec<u8, 256> = vec.into_bytes()?;

                    log::trace!("Overwriting index {:?} of a byte vector containing {:?} with {:?}", &idx, &vec, &value);

                    *vec.get_mut(idx)? = value.into_truncated_u8()?;

                    Some(Value::Bytes(vec))
                })?,
                OpCode::BAppend => self.do_binop(|v1, v2| {
                    let mut v1: CatVec<u8, 256> = v1.into_bytes()?;
                    let v2: CatVec<u8, 256> = v2.into_bytes()?;

                    log::trace!("Appending a vector that contains {:?} to a vector that contains {:?}", &v2, &v1);

                    v1.append(v2);

                    Some((Value::Bytes(v1), false))
                })?,
                OpCode::BSlice => self.do_triop(|vec, beginning_value, end_value| {
                    let beginning: usize = beginning_value.into_u16()? as usize;
                    let end: usize = end_value.into_u16()? as usize;

                    match vec {
                        Value::Bytes(mut vec) => {
                            let is_end_greater_or_equal_to_vector_length: bool = end >= vec.len();
                            let is_end_less_than_or_equal_to_beginning: bool = end <= beginning;

                            if is_end_greater_or_equal_to_vector_length || is_end_less_than_or_equal_to_beginning {
                                log::trace!("Tried to create a byte slice with invalid bounds. Returning an empty byte vector.");

                                Some(Value::Bytes(Default::default()))
                            } else {
                                log::trace!("Returning a byte slice from {:?} to {:?} from the byte vector containing: {:?}", beginning, end, &vec);

                                vec.slice_into(beginning..end);

                                Some(Value::Bytes(vec))
                            }
                        }
                        _ => {
                            log::trace!("Tried to call VSlice on something that was not a VM vector (Value::Vector).");

                            None
                        },
                    }
                })?,
                OpCode::BLength => self.do_monop(|vec| match vec {
                    Value::Bytes(vec) => {
                        let length: usize = vec.len();

                        log::trace!("Byte vector is of length: {}", length);

                        Some(Value::Int(U256::from(length as u64)))
                    },
                    _ => {
                        log::trace!("Tried to call BLength on something that was not a byte vector (Value::Bytes).");

                        None
                    },
                })?,
                // control flow
                OpCode::Bez(jgap) => {
                    let top = self.stack.pop()?;

                    if top.into_int() == Some(0u32.into()) {
                        log::trace!("In a call to Bez, the top of the stack was zero. Skipping to {}", &jgap);

                        self.pc += jgap as usize;

                        return Some(());
                    } else {
                        log::trace!("In a call to Bez, the top of the stack was not zero. It was {}. Not skipping any operations.", &jgap);
                    }
                }
                OpCode::Bnz(jgap) => {
                    let top = self.stack.pop()?;

                    if top.into_int() != Some(0u32.into()) {
                        log::trace!("In a call to Bnz, the top of the stack was not zero. Skipping to {}", &jgap);

                        self.pc += jgap as usize;
                        return Some(());
                    } else {
                        log::trace!("In a call to Bnz, the top of the stack was not zero. It was {}. Not skipping any operations.", &jgap);
                    }
                }
                OpCode::Jmp(jgap) => {
                    log::trace!("Jumping ahead to instruction number {}", &jgap);

                    self.pc += jgap as usize;
                    return Some(());
                }
                OpCode::Loop(iterations, op_count) => {
                    let is_iterations_positive: bool = iterations > 0;
                    let is_op_count_positive: bool = op_count > 0;

                    if is_iterations_positive && is_op_count_positive {
                        log::trace!("In a call to Loop, iterations and op_count were positive. Looping {} times.", iterations);

                        self.loop_state.push(LoopState {
                            // start after loop instruction
                            begin: self.pc,
                            // final op is inclusive
                            end: self.pc + op_count as usize - 1,
                            // dec happens after an iteration so -1 for first loop
                            iterations_left: iterations - 1,
                        });
                    } else {
                        if !is_iterations_positive {
                            log::trace!("In a call to Loop, iterations was not positive: {}. Skipping loop.", iterations);
                        } else if !is_op_count_positive {
                            log::trace!("In a call to Loop, op_count was not positive: {}. Skipping loop.", iterations);
                        } else {
                            log::trace!("In a call to Loop, neither iterations: {}, nor op_count were positive: {}. Skipping loop.", iterations, op_count);
                        }

                        return None;
                    }
                }
                // Conversions
                OpCode::BtoI => self.do_monop(|input_byte_vector| {
                    log::trace!("Converting bytes {:?} into an integer.", &input_byte_vector);

                    let bytes = input_byte_vector.into_bytes()?;
                    let bytes_vector: Vec<u8> = bytes.into();

                    let byte_vector_option: Option<[u8; 32]> = bytes_vector.try_into().ok();

                    match byte_vector_option {
                        Some(byte_vector) => {
                            log::trace!("In a call to BtoI, successfully converted input bytes to an integer.");

                            Some(Value::Int(U256::from_be_bytes(byte_vector)))
                        },
                        None => {
                            log::trace!("In a call to BtoI, failed to convert input bytes to an integer.");

                            None
                        },
                    }
                })?,
                OpCode::ItoB => self.do_monop(|input_integer| {
                    let number_option: Option<U256> = input_integer.into_int();

                    // I may not need this match, because it may not be able to fail, given that only positive integers are available.

                    match number_option {
                        Some(number) => {
                            log::trace!("In a call to ItoB, successfully converted input integer to bytes.");

                            Some(Value::Bytes(number.to_be_bytes().into()))
                        },
                        None => {
                            log::trace!("In a call to ItoB, failed to convert input integer to bytes.");

                            None
                        },
                    }
                })?,
                // literals
                OpCode::PushB(bts) => {
                    let bytes: Value = Value::from_bytes(&bts);

                    log::trace!("Pushing a byte vector containing {:?} onto the stack.", &bytes);

                    self.stack.push(bytes);
                }
                OpCode::PushI(num) => {

                    let number: Value = Value::Int(num);

                    log::trace!("Pushing the integer {:?} onto the stack.", &number);

                    self.stack.push(number)
                },
                OpCode::PushIC(number) => {
                    let integer: Value = Value::Int(number);

                    log::trace!("PushIC called. Pushing the integer {:?} onto the stack.", &integer);

                    self.stack.push(integer)
                },
                OpCode::TypeQ => self.do_monop(|input| {
                    match input {
                        Value::Int(integer) => {
                            log::trace!("In a call to TypeQ, the input was an integer: {:?}. Returning 0 to the stack.", integer);

                            Some(Value::Int(0u32.into()))
                        }
                        Value::Bytes(byte_vector) => {
                            log::trace!("In a call to TypeQ, the input was a byte vector containing: {:?}. Returning 1 to the stack.", byte_vector);

                            Some(Value::Int(1u32.into()))
                        }
                        Value::Vector(vector) => {
                            log::trace!("In a call to TypeQ, the input was a vector containing: {:?}. Returning 2 to the stack.", vector);

                            Some(Value::Int(2u32.into()))
                        }
                    }
                })?,
                // dup
                OpCode::Dup => {
                    let value: Value = self.stack.pop()?;

                    log::trace!("Dup called. Duplicating: {:?} on the stack.", &value);

                    self.stack.push(value.clone());
                    self.stack.push(value);
                }
                OpCode::Oflo => {
                    self.stack.push(Value::Int(U256::from(self.overflow)));
                    self.overflow = false;
                }
                OpCode::Cloflo => {
                    self.overflow = false;
                }
            }
            Some(())
        };
        let res: Option<()> = inner();
        self.update_pc_state();

        res
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use ethnum::U256;

    #[test]
    fn instant_overhead() {
        let start = Instant::now();
        let mut elapsed = Duration::from_secs(0);
        for _ in 0..10000 {
            let begin = Instant::now();
            elapsed += begin.elapsed(); // prevents optimizing away
        }
        eprintln!(
            "10000 iterations is {:?} (dummy {:?})",
            start.elapsed(),
            elapsed
        )
    }

    #[test]
    fn add_speed() {
        let start = Instant::now();
        let mut sum = U256::from(0u64);
        for _ in 0..10000 {
            sum += sum; // prevents optimizing away
        }
        eprintln!(
            "10000 iterations is {:?} (dummy {:?})",
            start.elapsed(),
            sum
        )
    }
}
