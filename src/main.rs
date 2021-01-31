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

#[derive(Clone, Copy, Debug)]
pub enum InsnException {
    Invalid,
    WrongType,
    NotTopFrame,
}

fn friendly_hex_u32(x: u32) -> String {
    format!("{:04X}_{:04X}", x >> 16, x & 0xFFFF)
}

pub struct Machine {
    pub x: XData,
    pub pc: u32,
    pub fp: ObjPtr,
    pub tos: u32,
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
        let tos = mem.len() as u32;

        Self { x: XData::I32(0), pc: 0, fp, tos, mem }
    }

    // TODO: This should be write_stack() and should write to a fmt::Write.
    pub fn print_stack(&self) {
        let mut fp = self.fp.0;
        while fp != 0 {
            let prev = self.load_u32(fp + 12);
            println!("#{}:", friendly_hex_u32(fp));
            println!("  cap  = #{}", friendly_hex_u32(self.load_u32(fp)));
            println!("  size = #{}", friendly_hex_u32(self.load_u32(fp + 4)));
            println!("  base = #{}", friendly_hex_u32(self.load_u32(fp + 8)));
            println!("  prev = #{}", friendly_hex_u32(prev));
            println!("  ret  = #{}", friendly_hex_u32(self.load_u32(fp + 16)));
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
                    let cap = self.load_u32(p + 4);
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

        self.pc += 4;

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
                        if id == ItemId(0) {
                            // Push new frame.
                            let cap = self.load_u32(self.fp.0);
                            if self.tos != self.fp.0 + OBJ_HEADER_SIZE + cap {
                                return Err(InsnException::NotTopFrame);
                            }
                            let new_tos = self.tos + OBJ_HEADER_SIZE + xv;
                            let new_tos = (new_tos + 1) & !0x3;
                            self.mem.resize(new_tos as usize, 0);
                            self.store_u32(self.tos, xv); // cap
                            self.store_u32(self.tos + 8, self.fp.0); // base
                            self.store_u32(self.tos + 12, self.fp.0); // prev
                            self.fp = ObjPtr(self.tos);
                            self.tos = new_tos;
                        } else {
                            // Push new named object.
                            unimplemented!();
                        }
                    },
                    XData::Object(_xv) => {
                        if id == ItemId(0) {
                            // Push existing object.
                            unimplemented!();
                        } else {
                            return Err(InsnException::WrongType);
                        }
                    },
                    _ => return Err(InsnException::WrongType),
                }
            },
            _ => unimplemented!(),
        }

        Ok(())
    }
}

fn main() {
    // TODO: CLI option to run built-in program that compiles input into
    // bytecode.

    let mut m = Machine::new(&[
        Insn::Push(0).as_u32(),
    ]);
    m.print_stack();
    m.step().unwrap();
    m.print_stack();
    m.step().unwrap();
    m.print_stack();
}
