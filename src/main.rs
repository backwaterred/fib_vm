
mod fisa {

    static NUM_REGS:      usize = 8;
    static MEMSIZE_BYTES: usize = 2*64;

    static OP_LEN:        u8 = 3;
    static REG_LEN:       u8 = 3;
    static INST_LEN:      u8 = 2*8;

    static REG1_MASK: u16 = 0b0001110000000000;
    static IV10_MASK: u16 = 0b0000001111111111;
    static REG2_MASK: u16 = 0b0000001110000000;
    static IV7_MASK:  u16 = 0b0000000001111111;
    static REG3_MASK: u16 = 0b0000000001110000;

    static REG1_SHIFT: u8 = INST_LEN - OP_LEN - REG_LEN;
    static REG2_SHIFT: u8 = INST_LEN - OP_LEN - REG_LEN - REG_LEN;
    static REG3_SHIFT: u8 = INST_LEN - OP_LEN - REG_LEN - REG_LEN - REG_LEN;

    static HALT_ADDR: Addr = 0b0000000001111111;

    // ---------- DATATYPES ----------
    type Reg = u16;
    type Addr = usize;

    enum Instruction {

        // OP- REG IVAL10----
        LoadImm(usize, u16),

        // OP- REG REG IVAL7--
        AddImm(usize, usize, u16),

        // OP- REG REG REG X4--
        AddReg(usize, usize, usize),

        // OP- REG REG IVAL7--
        JmpLt(usize, usize, Addr),

        // OP- REG X10-------
        SysPrint(usize),

        // OP---------------
        Halt,
    }

    pub struct Machine {
        regs: Vec<Reg>,
        mem: Vec<u8>,
        ip: Addr, // instruction pointer (next instruction)
    }

    // ---------- PARSING ----------
    fn parse(instr: &u16) -> Result<Instruction, ()> {

        let opcode: u16 = instr >> (INST_LEN - OP_LEN);

        match opcode {
            0b000 => {
                let r = (instr & REG1_MASK) >> REG1_SHIFT;
                let val = instr & IV10_MASK;

                Ok(Instruction::LoadImm(r.into(), val))
            },
            0b001 => {
                let r1 = (instr & REG1_MASK) >> REG1_SHIFT;
                let r2 = (instr & REG2_MASK) >> REG2_SHIFT;
                let val = instr & IV7_MASK;

                Ok(Instruction::AddImm(r1.into(), r2.into(), val))
            },
            0b010 => {
                let r1 = (instr & REG1_MASK) >> REG1_SHIFT;
                let r2 = (instr & REG2_MASK) >> REG2_SHIFT;
                let r3 = (instr & REG3_MASK) >> REG3_SHIFT;

                Ok(Instruction::AddReg(r1.into(), r2.into(), r3.into()))
            },
            0b011 => {
                let r1 = (instr & REG1_MASK) >> REG1_SHIFT;
                let r2 = (instr & REG2_MASK) >> REG2_SHIFT;
                let addr = instr & IV7_MASK;

                Ok(Instruction::JmpLt(r1.into(), r2.into(), addr.into()))
            },
            0b100 => {
                let r1 = (instr & REG1_MASK) >> REG1_SHIFT;

                Ok(Instruction::SysPrint(r1.into()))
            },
            0b111 =>
                Ok(Instruction::Halt),
            _ =>
                Err(()),
        }
    }

    // ---------- MACHINE ----------
    impl Machine {

        pub fn new() -> Machine {

            let mut regs = Vec::new();
            for _r in 0..NUM_REGS {
                regs.push(0);
            }

            let mem = vec![0; MEMSIZE_BYTES];

            Machine {
                regs,
                mem,
                ip: 0,
            }
        }

        pub fn get_reg(&self, idx: usize) -> Option<u16>
        {
            if let Some(v) = self.regs.get(idx) {
                Some(*v)
            } else {
                None
            }
        }

        pub fn set_reg(&mut self, idx: usize, val: u16)
        {
            self.regs[idx] = val;
        }

        pub fn get_ip(&self) -> Addr {
            self.ip
        }

        pub fn run(&mut self, addr: Addr)
        {
            self.ip = addr;
           
            while self.ip != HALT_ADDR {
                let inst = self.fetch();

                if let Ok(inst) = parse(&inst) {
                    self.apply(inst)
                }
            }
        }

        pub fn defetch(src: &Vec<u16>) -> Vec<u8>
        {
            let mut dst: Vec<u8> = Vec::new();

            for w in src {
                let bytes = w.to_be_bytes();
                dst.push(bytes[0]);
                dst.push(bytes[1]);
            }

            dst
        }

        // Overwrites memory from the given index until the end of the vector.
        pub fn memcpy(&mut self, src: &[u8], start_addr: Addr)
        {
            for addr in 0..src.len() {
                self.mem[start_addr + addr] = src[addr];
            }
        }

        fn fetch(&mut self) -> u16
        {
            let ip = self.ip;
            self.ip += 2;

            u16::from_be_bytes([self.mem[ip], self.mem[ip+1]])
        }

        // Apply the given instruction to this machine
        // EFFECTS: Mutates the state of the current machine
        fn apply(&mut self, inst: Instruction)
        {
            match inst {
                Instruction::LoadImm(r, iv) => {
                    self.regs[r] = iv
                },
                Instruction::AddImm(r1, r2, iv) => {
                    self.regs[r1] = self.regs[r2] + iv
                },
                Instruction::AddReg(r1, r2, r3) => {
                    self.regs[r1] = self.regs[r2] + self.regs[r3]
                },
                Instruction::JmpLt(r1, r2, addr) => {
                    if self.regs[r1] < self.regs[r2] {
                        self.ip = addr
                    }
                },
                Instruction::SysPrint(r) => {
                    println!("r{}: {}", r, self.regs[r])
                },
                Instruction::Halt =>
                    self.ip = HALT_ADDR,
            }
        }
    }

    // ---------- TESTING ----------
    #[cfg(test)]
    mod test {

        use super::*;

        fn run_ins(ins: &Vec<u16>) -> Machine {
            let mut m = Machine::new();
            for inst in ins {
                let inst = parse(inst).unwrap();
                m.apply(inst);
            }

            m
        }

        #[test]
        fn test_new_machine() {
            let m = Machine::new();

            for r in 0..NUM_REGS {
                assert_eq!(0, m.get_reg(r).unwrap());
            }
        }

        #[test]
        fn edge_val_load_imm() {

            let ins = vec![
                0b0000001111111111,
                0b0000010000000000
            ];

            let m = run_ins(&ins);

            assert_eq!(0b1111111111, m.get_reg(0).unwrap());
            assert_eq!(0, m.get_reg(1).unwrap());
        }

        #[test]
        fn all_reg_load_imm() {

            let ins = vec![
                0b0000000000000000,
                0b0000010000000001,
                0b0000100000000010,
                0b0000110000000011,
                0b0001000000000100,
                0b0001010000000101,
                0b0001100000000110,
                0b0001110000000111,
            ];

            let m = run_ins(&ins);

            for n in 0..ins.len() {
                assert_eq!(n as u16, m.get_reg(n).unwrap());
            }
        }


        #[test]
        fn add_imm_r2_iv() {

            let ins = vec![
                0b0000010000000010,
                0b0011110010000100,
            ];

            let m = run_ins(&ins);

            assert_eq!(0b110, m.get_reg(7).unwrap());
        }
      
        #[test]
        fn add_imm_r1_r2_iv() {

            let ins = vec![
                0b0000000000000001,
                0b0000010000000010,
                0b0011110000000100,
            ];

            let m = run_ins(&ins);

            assert_eq!(0b101, m.get_reg(7).unwrap());
        }

        #[test]
        fn add_reg_r1_r2_r3() {

            let ins = vec![
                0b0000010000000001,
                0b0000100000000010,
                0b0000110000000100,
                0b0100010100110000,
            ];

            let m = run_ins(&ins);

            assert_eq!(0b110, m.get_reg(1).unwrap());
        }

        #[test]
        fn add_reg_r1_r1_r1() {

            let ins = vec![
                0b0000010000000001,
                0b0100010010010000,
            ];

            let m = run_ins(&ins);

            assert_eq!(0b010, m.get_reg(1).unwrap());
        }

        #[test]
        fn jmp_nlt() {

            let ins = vec![
                0b0000010000000001,
                0b0000110000000001,
                0b0110010111111111,
            ];

            let m = run_ins(&ins);

            assert_eq!(0, m.get_ip())

        }

        #[test]
        fn jmp_lt() {

            let ins = vec![
                0b0000010000000001,
                0b0000110000000010,
                0b0110010111111111,
            ];

            let m = run_ins(&ins);

            assert_eq!(0b1111111, m.get_ip())

        }

        #[test]
        fn all_reg_sys_print() {

            let ins = vec![
                0b0000000000000000,
                0b0000010000000001,
                0b0000100000000010,
                0b0000110000000011,
                0b0001000000000100,
                0b0001010000000101,
                0b0001100000000110,
                0b0001110000000111,

                0b1000000000000000,
                0b1000010000000000,
                0b1000100000000000,
                0b1000110000000000,
                0b1001000000000000,
                0b1001010000000000,
                0b1001100000000000,
                0b1001110000000000,
            ];

            let _m = run_ins(&ins);

            // Rust runs each test in it's own thread 
            // and doesn't display printed output unless the test fails
            // panic!();
        }
    }
}

use fisa::Machine;

fn main() {
    println!("Starting FISA Machine");

    // Calling conventions:
    // Return value in r0
    // Params passed in regs starting at r1

    // Psudo-code
    // Fib n
    //   n0 = 0
    //   n1 = 1
    //   i = 1
    //   start:
    //     if n < i goto end
    //     nx = n0 + n1
    //     n0 = n1
    //     n1 = nx
    //     i++
    //     goto start
    //   end:
    //   return n

    let fib = vec![
        // Move param(s)
        0b0011110010000000, // r7 <- r1
        // loop preamble
        0b0000000000000000, // n0 = 0
        0b0000010000000001, // n1 = 1
        0b0000100000000000, // nx = 0
        0b0000110000000001, // i = 1
        // loop body
        0b0111110110010110, // if (n < i) jmp +22
        0b0100100000010000, // nx = n0 + n1
        0b0010000010000000, // n0 = n1 + 0
        0b0010010100000000, // n1 = nx + 0
        0b0010110110000001, // i = i + 1
        0b0111001110001010, // if (0 < n) jmp +10
        0b1000000000000000, // print r0
        0b1110000000000000  // halt
    ];

    let fib = Machine::defetch(&fib);
    let mut m = Machine::new();
    m.memcpy(&fib, 0);

    m.set_reg(1, 0);
    m.run(0); // -> 0

    m.set_reg(1, 1);
    m.run(0); // -> 1

    m.set_reg(1, 2);
    m.run(0); // -> 1

    m.set_reg(1, 3);
    m.run(0); // -> 2

    m.set_reg(1, 4);
    m.run(0); // -> 3

    m.set_reg(1, 5);
    m.run(0); // -> 5

    m.set_reg(1, 6);
    m.run(0); // -> 3
}
