/// Heap address where the transaction trying to spend the coin encumbered by this covenant (spender) is put
pub const HADDR_SPENDER_TX: u16 = 0;
/// Heap address where the spender's hash is put.
pub const HADDR_SPENDER_TXHASH: u16 = 1;
/// Heap address where the *parent* (the transaction that created the coin now getting spent)'s hash is put
pub const HADDR_PARENT_TXHASH: u16 = 2;
/// Heap address where the index, at the parent, of the coin being spent is put. For example, if we are spending the third output of some transaction, `Heap[ADDR_PARENT_INDEX] = 2`.
pub const HADDR_PARENT_INDEX: u16 = 3;
/// Heap address where the hash of the running covenant is put.
pub const HADDR_SELF_HASH: u16 = 4;
/// Heap address where the face value of the coin being spent is put.
pub const HADDR_PARENT_VALUE: u16 = 5;
/// Heap address where the denomination of the coin being spent is put.
pub const HADDR_PARENT_DENOM: u16 = 6;
/// Heap address where the additional data of the coin being spent is put.
pub const HADDR_PARENT_ADDITIONAL_DATA: u16 = 7;
/// Heap address where the height of the parent is put.
pub const HADDR_PARENT_HEIGHT: u16 = 8;
/// Heap address where the "spender index" is put. For example, if this coin is spent as the first input of the spender, then `Heap[ADDR_SPENDER_INDEX] = 0`.
pub const HADDR_SPENDER_INDEX: u16 = 9;
/// Heap address where the header of the last block is put. If the covenant is being evaluated for a transaction in block N, this is the header of block N-1.
pub const HADDR_LAST_HEADER: u16 = 10;

pub(crate) const OPCODE_NOOP: u8 = 0x09;

pub(crate) const OPCODE_ADD: u8 = 0x10;
pub(crate) const OPCODE_SUB: u8 = 0x11;
pub(crate) const OPCODE_MUL: u8 = 0x12;
pub(crate) const OPCODE_DIV: u8 = 0x13;
pub(crate) const OPCODE_REM: u8 = 0x14;
pub(crate) const OPCODE_EXP: u8 = 0x15;

pub(crate) const OPCODE_AND: u8 = 0x20;
pub(crate) const OPCODE_OR: u8 = 0x21;
pub(crate) const OPCODE_XOR: u8 = 0x22;
pub(crate) const OPCODE_NOT: u8 = 0x23;
pub(crate) const OPCODE_EQL: u8 = 0x24;
pub(crate) const OPCODE_LT: u8 = 0x25;
pub(crate) const OPCODE_GT: u8 = 0x26;
pub(crate) const OPCODE_SHL: u8 = 0x27;
pub(crate) const OPCODE_SHR: u8 = 0x28;

pub(crate) const OPCODE_HASH: u8 = 0x30;
pub(crate) const OPCODE_SIGEOK: u8 = 0x32;

pub(crate) const OPCODE_LOAD: u8 = 0x40;
pub(crate) const OPCODE_STORE: u8 = 0x41;
pub(crate) const OPCODE_LOADIMM: u8 = 0x42;
pub(crate) const OPCODE_STOREIMM: u8 = 0x43;

pub(crate) const OPCODE_VREF: u8 = 0x50;
pub(crate) const OPCODE_VAPPEND: u8 = 0x51;
pub(crate) const OPCODE_VEMPTY: u8 = 0x52;
pub(crate) const OPCODE_VLENGTH: u8 = 0x53;
pub(crate) const OPCODE_VSLICE: u8 = 0x54;
pub(crate) const OPCODE_VSET: u8 = 0x55;
pub(crate) const OPCODE_VPUSH: u8 = 0x56;
pub(crate) const OPCODE_VCONS: u8 = 0x57;

pub(crate) const OPCODE_BREF: u8 = 0x70;
pub(crate) const OPCODE_BAPPEND: u8 = 0x71;
pub(crate) const OPCODE_BEMPTY: u8 = 0x72;
pub(crate) const OPCODE_BLENGTH: u8 = 0x73;
pub(crate) const OPCODE_BSLICE: u8 = 0x74;
pub(crate) const OPCODE_BSET: u8 = 0x75;
pub(crate) const OPCODE_BPUSH: u8 = 0x76;
pub(crate) const OPCODE_BCONS: u8 = 0x77;

pub(crate) const OPCODE_JMP: u8 = 0xa0;
pub(crate) const OPCODE_BEZ: u8 = 0xa1;
pub(crate) const OPCODE_BNZ: u8 = 0xa2;

pub(crate) const OPCODE_LOOP: u8 = 0xb0;

pub(crate) const OPCODE_ITOB: u8 = 0xc0;
pub(crate) const OPCODE_BTOI: u8 = 0xc1;
pub(crate) const OPCODE_TYPEQ: u8 = 0xc2;

pub(crate) const OPCODE_PUSHB: u8 = 0xf0;
pub(crate) const OPCODE_PUSHI: u8 = 0xf1;
pub(crate) const OPCODE_PUSHIC: u8 = 0xf2;

pub(crate) const OPCODE_CLOFLO: u8 = 0xfd;
pub(crate) const OPCODE_OFLO: u8 = 0xfe;
pub(crate) const OPCODE_DUP: u8 = 0xff;
