use core::cmp::max;
use core::convert::TryInto;

const OBJ_HEADER_SIZE: u32 = 20;

#[derive(Clone, Copy, Debug)]
pub enum Insn {
    Def(u32),
    Set(u32),
    Push(u32),
    Pop,
    Call,
    Jump(u32),
    Imm(u32),
    Val(u32),
}

impl Insn {
    pub fn from_u32(i: u32) -> Self {
        use Insn::*;
        let op = i >> 29;
        let n = i & 0x1FFF_FFFF;
        match op {
            0 => Def(n),
            1 => Set(n),
            2 => Push(n),
            3 => Pop,
            4 => Call,
            5 => Jump(n),
            6 => Imm(n),
            7 => Val(n),
            _ => unreachable!(),
        }
    }

    pub fn as_u32(&self) -> u32 {
        use Insn::*;
        match self {
            &Def(n) => (0<<29) | n,
            &Set(n) => (1<<29) | n,
            &Push(n) => (2<<29) | n,
            &Pop => 3<<29,
            &Call => 4<<29,
            &Jump(n) => (5<<29) | n,
            &Imm(n) => (6<<29) | n,
            &Val(n) => (7<<29) | n,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DataPtr(u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ItemId(u32);

#[derive(Clone, Copy, Debug)]
pub struct ObjPtr(u32);

#[derive(Clone, Copy, Debug)]
pub enum XData {
    BuiltinCode(u32), // index (0 is reserved for future extensions)
    Code(u32), // pointer
    I32(u32),
    Object(u32), // pointer
}

#[derive(Clone, Copy, Debug)]
pub enum Type {
    BuiltinCode,
    Code,
    I32,
    Object,
}

pub fn item_header_from_u32(h: u32) -> (Type, ItemId) {
    use Type::*;
    let ty = h >> 29;
    let id = h & 0x1FFF_FFFF;
    (match ty {
        0 => BuiltinCode,
        1 => Code,
        2 => I32,
        3 => Object,
        _ => unreachable!(),
    }, ItemId(id))
}

pub fn item_header_to_u32(ty: Type, id: ItemId) -> u32 {
    use Type::*;
    let ty = match ty {
        BuiltinCode => 0,
        Code => 1,
        I32 => 2,
        Object => 3,
    };
    (ty<<29) | id.0
}

#[derive(Clone, Copy, Debug)]
pub enum InsnException {
    Invalid,
    WrongType,
    UnalignedCap,
    NotTopFrame,
}

fn friendly_hex_u32(x: u32) -> String {
    format!("{:04X}_{:04X}", x >> 16, x & 0xFFFF)
}

pub struct Machine {
    pub x: XData,
    pub pc: u32,
    pub fp: ObjPtr,
    pub mem: Vec<u8>,
}

impl Machine {
    pub fn new(code: &[u32]) -> Self {
        let mut mem = Vec::with_capacity(0x10_0000);
        for chunk in code.iter().map(|&i| i.to_le_bytes()) {
            mem.extend_from_slice(&chunk);
        }
        let fp = ObjPtr(mem.len() as u32);
        mem.resize(mem.len() + OBJ_HEADER_SIZE as usize, 0);
        Self { x: XData::I32(0), pc: 0, fp, mem }
    }

    // TODO: This should be write_stack() and should write to a fmt::Write.
    pub fn print_stack(&self) {
        let mut fp = self.fp.0;
        while fp != 0 {
            let prev = self.load_u32(fp + 12);
            println!("#{}:", friendly_hex_u32(fp));
            println!("  cap  = #{}", friendly_hex_u32(self.load_u32(fp + 0)));
            println!("  size = #{}", friendly_hex_u32(self.load_u32(fp + 4)));
            println!("  base = #{}", friendly_hex_u32(self.load_u32(fp + 8)));
            println!("  prev = #{}", friendly_hex_u32(prev));
            println!("  ret  = #{}", friendly_hex_u32(self.load_u32(fp + 16)));
            if fp == prev {
                unreachable!("infinite `prev` loop");
            }
            fp = prev;
        }
    }

    pub fn load_u32(&self, addr: u32) -> u32 {
        u32::from_le_bytes(
            self.mem[addr as usize .. (addr+4) as usize].try_into().unwrap())
    }

    pub fn store_u32(&mut self, addr: u32, val: u32) {
        self.mem[addr as usize .. (addr+4) as usize].copy_from_slice(
            &val.to_le_bytes());
    }

    pub fn find_in_frame(&self, fp: ObjPtr, id: ItemId) -> Option<DataPtr> {
        let size = self.load_u32(fp.0);
        let mut p = fp.0 + OBJ_HEADER_SIZE;

        while p < fp.0 + size {
            let (ty, id2) = item_header_from_u32(self.load_u32(p));
            if id2 == id {
                return Some(DataPtr(p + 4));
            }
            p += 4 + match ty {
                Type::BuiltinCode => 4,
                Type::Code => 4,
                Type::I32 => 4,
                Type::Object => {
                    let cap = self.load_u32(p + 4 + 0);
                    OBJ_HEADER_SIZE + cap
                },
            };
        }
        assert_eq!(p, fp.0 + size);
        None
    }

    pub fn step(&mut self) -> Result<(), InsnException> {
        let insn_u32 = self.load_u32(self.pc);
        let insn = Insn::from_u32(insn_u32);

        match insn {
            Insn::Def(id) => {
                assert_eq!(id & 0xE000_0000, 0);
                let id = ItemId(id);
                if id == ItemId(0) {
                    return Err(InsnException::Invalid);
                }
                unimplemented!();
            },
            Insn::Push(id) => {
                assert_eq!(id & 0xE000_0000, 0);
                let id = ItemId(id);
                match self.x {
                    XData::I32(xv) => {
                        let cap = self.load_u32(self.fp.0);
                        if self.fp.0 + OBJ_HEADER_SIZE + cap
                                != self.mem.len() as u32 {
                            return Err(InsnException::NotTopFrame);
                        }
                        if xv & 0x3 != 0 {
                            return Err(InsnException::UnalignedCap);
                        }

                        if id == ItemId(0) {
                            // Push new frame.
                            let delta = OBJ_HEADER_SIZE + xv;
                            let new_fp = self.fp.0 + delta;
                            self.mem.resize(self.mem.len() + delta as usize, 0);

                            self.store_u32(new_fp + 0, xv); // cap
                            self.store_u32(new_fp + 8, self.fp.0); // base
                            self.store_u32(new_fp + 12, self.fp.0); // prev

                            self.fp = ObjPtr(new_fp);
                        } else {
                            // Push new named object.
                            let size_delta = 4 + OBJ_HEADER_SIZE + xv;
                            let size = self.load_u32(self.fp.0 + 4);
                            let new_obj =
                                self.fp.0 + OBJ_HEADER_SIZE + size + 4;
                            let new_size = size + size_delta;
                            let new_cap = max(cap, new_size);
                            let new_tos = self.fp.0 + OBJ_HEADER_SIZE + new_cap;
                            self.mem.resize(new_tos as usize, 0);

                            self.store_u32(new_obj - 4, item_header_to_u32(
                                Type::Object, id));
                            self.store_u32(new_obj + 0, xv); // cap
                            self.store_u32(new_obj + 8, self.fp.0); // base
                            self.store_u32(new_obj + 12, self.fp.0); // prev

                            self.store_u32(self.fp.0 + 0, new_cap);
                            self.store_u32(self.fp.0 + 4, new_size);

                            self.fp = ObjPtr(new_obj);
                        }
                    },
                    XData::Object(xid) => {
                        if id == ItemId(0) {
                            // Push existing object.
                            let xid = ItemId(xid);
                            let _ = self.find_in_frame(self.fp, xid);
                            unimplemented!();
                        } else {
                            return Err(InsnException::WrongType);
                        }
                    },
                    _ => return Err(InsnException::WrongType),
                }

                self.pc += 4;
            },
            _ => unimplemented!(),
        }

        Ok(())
    }
}

fn main() {
    // TODO: CLI option to run built-in program that compiles input into
    // bytecode.

    let prog: Vec<_> = [
        Insn::Push(0),
        Insn::Push(1),
    ].iter().map(|i| i.as_u32()).collect();

    let mut m = Machine::new(&prog);
    loop {
        m.print_stack();
        println!();
        if let Err(e) = m.step() {
            eprintln!("exception: {:?} at #{}", e, friendly_hex_u32(m.pc));
            break;
        }
    }
    m.print_stack();
}
