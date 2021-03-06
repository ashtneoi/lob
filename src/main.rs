use core::convert::TryInto;

const OBJ_HEADER_SIZE: u32 = 20;

#[derive(Clone, Copy, Debug)]
pub enum Inherent {
    Call,
    Pop,
    Alloc,
    Unknown(u32),
}

impl Inherent {
    fn from_u32(n: u32) -> Inherent {
        use Inherent::*;
        match n {
            0 => Call,
            1 => Pop,
            2 => Alloc,
            _ => Unknown(3),
        }
    }

    fn as_u32(&self) -> u32 {
        use Inherent::*;
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
    Inh(Inherent),
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
            3 => Inh(Inherent::from_u32(n)),
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
            Inh(i) => (3<<29) | i.as_u32(),
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
            Inh(i) => i.as_u32(),
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

impl ObjPtr {
    fn body_offset(&self, n: u32) -> u32 {
        self.0 + OBJ_HEADER_SIZE + n
    }

    pub fn cap(&self, mem: &Mem) -> u32 {
        mem.load_u32(self.0 + 0)
    }

    pub fn size(&self, mem: &Mem) -> u32 {
        mem.load_u32(self.0 + 4)
    }

    pub fn base(&self, mem: &Mem) -> Option<ObjPtr> {
        let p = mem.load_u32(self.0 + 8);
        match p {
            0 => None,
            _ => Some(ObjPtr(p)),
        }
    }

    pub fn prev(&self, mem: &Mem) -> Option<ObjPtr> {
        let p = mem.load_u32(self.0 + 12);
        match p {
            0 => None,
            _ => Some(ObjPtr(p)),
        }
    }

    pub fn ret(&self, mem: &Mem) -> Option<u32> {
        let r = mem.load_u32(self.0 + 16);
        match r {
            0 => None,
            _ => Some(r),
        }
    }

    pub fn set_cap(&self, mem: &mut Mem, val: u32) {
        mem.store_u32(self.0 + 0, val);
    }

    pub fn set_size(&self, mem: &mut Mem, val: u32) {
        mem.store_u32(self.0 + 4, val);
    }

    pub fn set_base(&self, mem: &mut Mem, val: ObjPtr) {
        mem.store_u32(self.0 + 8, val.0);
    }

    pub fn set_prev(&self, mem: &mut Mem, val: ObjPtr) {
        mem.store_u32(self.0 + 12, val.0);
    }

    pub fn set_ret(&self, mem: &mut Mem, val: u32) {
        mem.store_u32(self.0 + 16, val);
    }
}

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
    WrongType,
    UnalignedCap,
    NotTopFrame,
    ItemNotFound,
    ItemExistsInFrame(ItemPtr),
    FrameFull,
    StackUnderflow,
}

fn friendly_hex_u32(x: u32) -> String {
    format!("{:04X}_{:04X}", x >> 16, x & 0xFFFF)
}

pub struct Mem(Vec<u8>);

impl Mem {
    pub fn load_u32(&self, addr: u32) -> u32 {
        u32::from_le_bytes(
            self.0[addr as usize .. (addr+4) as usize].try_into().unwrap())
    }

    pub fn store_u32(&mut self, addr: u32, val: u32) {
        self.0[addr as usize .. (addr+4) as usize].copy_from_slice(
            &val.to_le_bytes());
    }
}

pub struct Machine {
    pub x: XData,
    pub pc: u32,
    pub fp: ObjPtr,
    pub gp: ObjPtr,
    pub mem: Mem,
}

impl Machine {
    pub fn new(code: &[u32]) -> Self {
        let mut mem = Vec::with_capacity(4*code.len() + 0x100);
        for chunk in code.iter().map(|&i| i.to_le_bytes()) {
            mem.extend_from_slice(&chunk);
        }
        let fp = ObjPtr(mem.len() as u32);
        mem.resize(mem.len() + OBJ_HEADER_SIZE as usize, 0);
        Self { x: XData::I32(0), pc: 0, fp, gp: fp, mem: Mem(mem) }
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
            self.print_obj(ObjPtr(fp));
            if fp == prev {
                unreachable!("infinite `prev` loop");
            }
            fp = prev;
        }
    }

    pub fn print_obj(&self, obj: ObjPtr) {
        // TODO: This should probably belong to ObjPtr, not Machine.

        let size = obj.size(&self.mem);
        let mut p = obj.body_offset(0);
        while p < obj.body_offset(size) {
            let (ty, id) = item_header_from_u32(self.load_u32(p));
            // TODO: Don't use id.0 here, just teach it Debug.
            println!("  id #{}: {:?}", friendly_hex_u32(id.0), ty);
            p += 4 + match ty {
                Type::BuiltinCode => 4,
                Type::Code => 4,
                Type::I32 => 4,
                Type::Object => {
                    let subobj = ObjPtr(p + 4);
                    let cap = subobj.cap(&self.mem);
                    OBJ_HEADER_SIZE + cap
                },
            };
        }
        // We can't assert that p == obj.body_offset(size), because frames
        // (except for the top one) can have a short cap and size if we're in a
        // frame created via `push "foo"`.
    }

    pub fn find_in_frame(&self, fp: ObjPtr, id: ItemId) -> Option<ItemPtr> {
        let size = self.load_u32(fp.0 + 4);
        let mut p = fp.0 + OBJ_HEADER_SIZE;

        while p < fp.body_offset(size) {
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
        assert_eq!(p, fp.body_offset(size));
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

    fn load_u32(&self, addr: u32) -> u32 {
        self.mem.load_u32(addr)
    }

    fn store_u32(&mut self, addr: u32, val: u32) {
        self.mem.store_u32(addr, val)
    }

    fn tos(&self) -> u32 {
        self.mem.0.len() as u32
    }

    fn cap(&self) -> u32 {
        self.fp.cap(&self.mem)
    }

    fn size(&self) -> u32 {
        self.fp.size(&self.mem)
    }

    fn base(&self) -> Option<ObjPtr> {
        self.fp.base(&self.mem)
    }

    fn prev(&self) -> Option<ObjPtr> {
        self.fp.prev(&self.mem)
    }

    fn ret(&self) -> Option<u32> {
        self.fp.ret(&self.mem)
    }

    fn set_tos(&mut self, val: u32) {
        self.mem.0.resize(val as usize, 0);
    }

    fn set_cap(&mut self, val: u32) {
        self.fp.set_cap(&mut self.mem, val);
        assert!(self.fp.body_offset(self.cap()) <= self.tos());
    }

    fn set_size(&mut self, val: u32) {
        self.fp.set_size(&mut self.mem, val)
    }

    fn set_base(&mut self, val: ObjPtr) {
        self.fp.set_base(&mut self.mem, val)
    }

    fn set_prev(&mut self, val: ObjPtr) {
        self.fp.set_prev(&mut self.mem, val)
    }

    fn set_ret(&mut self, val: u32) {
        self.fp.set_ret(&mut self.mem, val)
    }

    fn is_top_frame(&self) -> bool {
        let frame_end = self.fp.body_offset(self.cap());
        assert!(frame_end <= self.tos());
        frame_end == self.tos()
    }

    fn ensure_space(&mut self, new_size: u32) -> Result<(), InsnException> {
        if new_size > self.cap() {
            if self.is_top_frame() {
                self.set_tos(self.fp.body_offset(new_size));
                self.set_cap(new_size);
                Ok(())
            } else {
                Err(InsnException::FrameFull)
            }
        } else {
            Ok(())
        }
    }

    pub fn step(&mut self) -> Result<Option<XData>, InsnException> {
        let insn_u32 = self.load_u32(self.pc);
        let insn = Insn::from_u32(insn_u32);

        let old_pc = self.pc;

        match insn {
            Insn::Def(id) => {
                let id = ItemId(id);
                if id == ItemId(0) {
                    return Ok(Some(self.x));
                }
                if let Some(item) = self.find_in_frame(self.fp, id) {
                    return Err(InsnException::ItemExistsInFrame(item));
                }

                if let XData::I32(n) = self.x {
                    let size_delta = 4 + 4;
                    let new_size = self.size() + size_delta;

                    self.ensure_space(new_size)?;
                    self.store_u32(
                        self.fp.body_offset(self.size()),
                        item_header_to_u32(Type::I32, id));
                    self.store_u32(
                        self.fp.body_offset(self.size() + 4), n);

                    self.set_size(new_size);
                } else {
                    unimplemented!();
                }

                self.pc += 4;
            },
            Insn::Push(id) => {
                let id = ItemId(id);
                match self.x {
                    XData::I32(xv) => {
                        if self.fp.body_offset(self.cap()) != self.tos() {
                            return Err(InsnException::NotTopFrame);
                        }
                        if xv & 0x3 != 0 {
                            return Err(InsnException::UnalignedCap);
                        }

                        if id == ItemId(0) {
                            // Push new frame.
                            let new_fp = ObjPtr(
                                self.fp.body_offset(self.cap()));
                            self.set_tos(new_fp.body_offset(xv));

                            new_fp.set_cap(&mut self.mem, xv);
                            new_fp.set_size(&mut self.mem, 0);
                            new_fp.set_base(&mut self.mem, self.fp);
                            new_fp.set_prev(&mut self.mem, self.fp);
                            new_fp.set_ret(&mut self.mem, 0);

                            self.fp = new_fp;
                        } else {
                            // Push new named object.
                            let size_delta = 4 + OBJ_HEADER_SIZE + xv;
                            let old_size = self.size();
                            let new_size = old_size + size_delta;
                            self.ensure_space(new_size)?;

                            let new_obj_header = self.fp.body_offset(old_size);
                            let new_obj = ObjPtr(new_obj_header + 4);

                            self.store_u32(new_obj_header, item_header_to_u32(
                                Type::Object, id));
                            new_obj.set_cap(&mut self.mem, xv);
                            new_obj.set_size(&mut self.mem, 0);
                            new_obj.set_base(&mut self.mem, self.fp);
                            new_obj.set_prev(&mut self.mem, self.fp);
                            new_obj.set_ret(&mut self.mem, 0);

                            self.set_size(new_size);

                            self.fp = new_obj;
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
            Insn::Inh(intr) => {
                match intr {
                    Inherent::Pop => {
                        match self.fp.ret(&self.mem) {
                            Some(ret) => self.pc = ret,
                            None => self.pc += 4,
                        }

                        let old_fp = self.fp;
                        if let Some(new_fp) = self.prev() {
                            self.fp = new_fp;
                            let end = self.fp.body_offset(self.size());
                            if end >= old_fp.body_offset(0) {
                                assert_eq!(end, old_fp.body_offset(0));
                                // old_fp is a member of self.fp, so we have to
                                // expand self.fp so it'll fit.
                                let inner_end =
                                    old_fp.body_offset(old_fp.size(&self.mem));
                                let new_size =
                                    inner_end - self.fp.body_offset(0);
                                self.set_cap(new_size);
                                self.set_size(new_size);
                            }
                            self.set_tos(self.fp.body_offset(self.cap()));
                        } else {
                            return Err(InsnException::StackUnderflow);
                        }
                    },
                    _ => unimplemented!(),
                }
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

        assert_ne!(self.pc, old_pc);

        Ok(None)
    }
}

fn main() {
    // TODO: CLI option to run built-in program that compiles input into
    // bytecode.

    let prog: Vec<_> = [
        Insn::Val(0),

        Insn::Xlo(0),
        Insn::Push(0),
        Insn::Push(1),
        Insn::Xlo(0x1FFF_FFFF),
        Insn::Xhi(0x7),
        Insn::Def(1),
        Insn::Def(2),
        Insn::Def(3),
        Insn::Def(4),
        Insn::Xlo(0),
        Insn::Push(0),
        Insn::Inh(Inherent::Pop),
        Insn::Inh(Inherent::Pop),
        Insn::Inh(Inherent::Pop),

        Insn::Def(0),
    ].iter().map(|i| i.as_u32()).collect();

    let mut m = Machine::new(&prog);
    loop {
        println!("x = {:?}", m.x);
        m.print_stack();
        println!();
        println!("---");
        println!();
        match m.step() {
            Ok(Some(x)) => {
                println!("result: {:?} @ #{}", x, friendly_hex_u32(m.pc));
                break;
            },
            Ok(None) => (),
            Err(e) => {
                eprintln!("exception: {:?} @ #{}", e, friendly_hex_u32(m.pc));
                m.print_stack();
                break;
            },
        }
    }
}
