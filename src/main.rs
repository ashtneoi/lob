use core::cmp::max;
use core::convert::TryInto;

const OBJ_HEADER_SIZE: u32 = 20;

#[derive(Clone, Copy, Debug)]
pub enum Intrinsic {
    Call,
    Pop,
    Alloc,
    Unknown(u32),
}

impl Intrinsic {
    fn from_u32(n: u32) -> Intrinsic {
        use Intrinsic::*;
        match n {
            0 => Call,
            1 => Pop,
            2 => Alloc,
            _ => Unknown(3),
        }
    }

    fn as_u32(&self) -> u32 {
        use Intrinsic::*;
        match *self {
            Call => 0,
            Pop => 1,
            Alloc => 2,
            Unknown(n) => {
                assert!(n > 2);
                n
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Insn {
    Def(u32),
    Set(u32),
    Push(u32),
    Intr(Intrinsic),
    Jump(u32),
    Val(u32),
    Xlo(u32),
    Xhi(u32),
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
            3 => Intr(Intrinsic::from_u32(n)),
            4 => Jump(n),
            5 => Val(n),
            6 => Xlo(n),
            7 => Xhi(n),
            _ => unreachable!(),
        }
    }

    pub fn as_u32(&self) -> u32 {
        self.validate().unwrap();
        use Insn::*;
        match *self {
            Def(n) => (0<<29) | n,
            Set(n) => (1<<29) | n,
            Push(n) => (2<<29) | n,
            Intr(i) => (3<<29) | i.as_u32(),
            Jump(n) => (4<<29) | n,
            Val(n) => (5<<29) | n,
            Xlo(n) => (6<<29) | n,
            Xhi(n) => (7<<29) | n,
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        use Insn::*;
        let imm = match *self {
            Def(n) => n,
            Set(n) => n,
            Push(n) => n,
            Intr(i) => i.as_u32(),
            Jump(n) => n,
            Val(n) => n,
            Xlo(n) => n,
            Xhi(n) => {
                if n & 0x7 != n {
                    return Err("xhi immediate doesn't fit in bits 2..0");
                }
                n
            },
        };
        if imm & 0xE000_0000 == 0 {
            Ok(())
        } else {
            Err("immediate doesn't fit in bits 29..0")
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ItemPtr(u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ItemId(u32);

#[derive(Clone, Copy, Debug)]
pub struct ObjPtr(u32);

#[derive(Clone, Copy, Debug)]
pub enum XData {
    BuiltinCode(u32), // index (0 is reserved for future extensions)
    Code(u32), // pointer
    I32(u32),
    Object(ObjPtr),
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
    ItemNotFound,
    ItemExistsInFrame,
}

fn friendly_hex_u32(x: u32) -> String {
    format!("{:04X}_{:04X}", x >> 16, x & 0xFFFF)
}

pub struct Machine {
    pub x: XData,
    pub pc: u32,
    pub fp: ObjPtr,
    pub gp: ObjPtr,
    pub mem: Vec<u8>,
}

impl Machine {
    pub fn new(code: &[u32]) -> Self {
        let mut mem = Vec::with_capacity(4*code.len() + 0x100);
        for chunk in code.iter().map(|&i| i.to_le_bytes()) {
            mem.extend_from_slice(&chunk);
        }
        let fp = ObjPtr(mem.len() as u32);
        mem.resize(mem.len() + OBJ_HEADER_SIZE as usize, 0);
        Self { x: XData::I32(0), pc: 0, fp, gp: fp, mem }
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

    pub fn find_in_frame(&self, fp: ObjPtr, id: ItemId) -> Option<ItemPtr> {
        let size = self.load_u32(fp.0 + 4);
        let mut p = fp.0 + OBJ_HEADER_SIZE;

        while p < fp.0 + size {
            let (ty, id2) = item_header_from_u32(self.load_u32(p));
            if id2 == id {
                return Some(ItemPtr(p));
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
        assert_eq!(p, fp.0 + OBJ_HEADER_SIZE + size);
        None
    }

    pub fn find(&self, id: ItemId) -> Option<ItemPtr> {
        let mut fp = self.fp.0;
        while fp != 0 {
            let prev = self.load_u32(fp + 12);
            if let Some(item) = self.find_in_frame(self.fp, id) {
                return Some(item);
            }
            if fp == prev {
                unreachable!("infinite `prev` loop");
            }
            fp = prev;
        }
        None
    }

    fn tos(&self) -> u32 {
        self.mem.len() as u32
    }

    fn cap(&self) -> u32 {
        self.load_u32(self.fp.0 + 0)
    }

    fn size(&self) -> u32 {
        self.load_u32(self.fp.0 + 4)
    }

    fn base(&self) -> ObjPtr {
        ObjPtr(self.load_u32(self.fp.0 + 8))
    }

    fn prev(&self) -> ObjPtr {
        ObjPtr(self.load_u32(self.fp.0 + 12))
    }

    fn ret(&self) -> u32 {
        self.load_u32(self.fp.0 + 16)
    }

    fn set_tos(&mut self, val: u32) {
        self.mem.resize(val as usize, 0);
    }

    fn set_cap(&mut self, val: u32) {
        self.store_u32(self.fp.0 + 0, val);
    }

    fn set_size(&mut self, val: u32) {
        self.store_u32(self.fp.0 + 4, val);
    }

    fn set_base(&mut self, val: ObjPtr) {
        self.store_u32(self.fp.0 + 8, val.0);
    }

    fn set_prev(&mut self, val: ObjPtr) {
        self.store_u32(self.fp.0 + 12, val.0);
    }

    fn set_ret(&mut self, val: u32) {
        self.store_u32(self.fp.0 + 16, val);
    }

    pub fn step(&mut self) -> Result<Option<XData>, InsnException> {
        let insn_u32 = self.load_u32(self.pc);
        let insn = Insn::from_u32(insn_u32);

        match insn {
            Insn::Def(id) => {
                let id = ItemId(id);
                if id == ItemId(0) {
                    return Ok(Some(self.x));
                }
                if self.find_in_frame(self.fp, id).is_some() {
                    return Err(InsnException::ItemExistsInFrame);
                }

                unimplemented!();
            },
            Insn::Push(id) => {
                let id = ItemId(id);
                match self.x {
                    XData::I32(xv) => {
                        let cap = self.cap();
                        let tos = self.tos();
                        if self.fp.0 + OBJ_HEADER_SIZE + cap != tos {
                            return Err(InsnException::NotTopFrame);
                        }
                        if xv & 0x3 != 0 {
                            return Err(InsnException::UnalignedCap);
                        }

                        if id == ItemId(0) {
                            // Push new frame.
                            let mem_delta = OBJ_HEADER_SIZE + xv;
                            let new_fp = ObjPtr(self.fp.0 + mem_delta);
                            self.mem.resize((tos + mem_delta) as usize, 0);

                            let new_prev = self.fp;
                            self.fp = new_fp;

                            self.set_cap(xv);
                            self.set_base(new_prev);
                            self.set_prev(new_prev);
                        } else {
                            // Push new named object.
                            let size_delta = 4 + OBJ_HEADER_SIZE + xv;
                            let size = self.size();
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
                    XData::Object(ObjPtr(_p)) => {
                        if id == ItemId(0) {
                            // Push existing object.
                            unimplemented!();
                        } else {
                            return Err(InsnException::WrongType);
                        }
                    },
                    _ => return Err(InsnException::WrongType),
                }

                self.pc += 4;
            },
            Insn::Val(id) => {
                let id = ItemId(id);

                if id == ItemId(0) {
                    self.x = XData::Object(ObjPtr(self.gp.0));
                } else {
                    if let Some(ItemPtr(item)) = self.find(id) {
                        let (ty, _) = item_header_from_u32(self.load_u32(item));
                        self.x = match ty {
                            Type::BuiltinCode =>
                                XData::BuiltinCode(self.load_u32(item + 4)),
                            Type::Code =>
                                XData::Code(self.load_u32(item + 4)),
                            Type::I32 =>
                                XData::I32(self.load_u32(item + 4)),
                            Type::Object =>
                                XData::Object(ObjPtr(item + 4)),
                        }
                    } else {
                        return Err(InsnException::ItemNotFound);
                    }
                }

                self.pc += 4;
            },
            Insn::Xlo(n) => {
                self.x = XData::I32(n);

                self.pc += 4;
            },
            Insn::Xhi(n) => {
                if let XData::I32(n2) = self.x {
                    self.x = XData::I32((n2 & 0x1FFF_FFFF) | (n<<29));
                } else {
                    return Err(InsnException::WrongType);
                }

                self.pc += 4;
            },
            _ => unimplemented!(),
        }

        Ok(None)
    }
}

fn main() {
    // TODO: CLI option to run built-in program that compiles input into
    // bytecode.

    let prog: Vec<_> = [
        Insn::Push(0),
        Insn::Push(1),
        Insn::Val(0),
        Insn::Xlo(0x1FFF_FFFF),
        Insn::Xhi(0x7),
        Insn::Def(0),
    ].iter().map(|i| i.as_u32()).collect();

    let mut m = Machine::new(&prog);
    loop {
        println!("x = {:?}", m.x);
        m.print_stack();
        println!();
        match m.step() {
            Ok(Some(x)) => {
                println!("result: {:?} @ #{}", x, friendly_hex_u32(m.pc));
                break;
            },
            Err(e) => {
                eprintln!("exception: {:?} @ #{}", e, friendly_hex_u32(m.pc));
                m.print_stack();
                break;
            },
            _ => (),
        }
    }
}
