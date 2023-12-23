from iced_x86 import *
import random
from random import randint

class X64ObfuscatorLib:
    def __init__(self,code,start_address,base):
        self.code = code
        self.bitness = 64
        self.start_address = start_address
        self.formatter = Formatter(FormatterSyntax.NASM)
        self.base = base
        self.bbs_with_links = {}
    def load(self):
        bbs = []
        bb = []
        visited = []
        print('[*] start recursive disassembly..')
        targets = [Decoder(self.bitness, self.code, ip=self.start_address)]
        is_control_flow_end = False
        while len(targets) > 0:
            target = targets.pop()
            if target.ip in visited:
                continue
            visited.append(target.ip)
            #try:
            for insn in target:
                is_control_flow_end = False
                bb.append(insn)
                if insn.is_loop or \
                insn.is_loopcc or \
                insn.is_call_near or \
                insn.is_jcc_short_or_near or \
                insn.is_jkcc_short_or_near:
                    #print(f"{insn.ip:016X} {insn}")
                    is_control_flow_end = True
                    bbs.append(bb)
                    bb = []
                    insn.as_near_branch()
                    idx = insn.near_branch_target - self.base
                    idx_next = insn.next_ip - self.base
                    targets.append(Decoder(self.bitness, self.code[idx:], ip=insn.near_branch_target))
                    targets.append(Decoder(self.bitness, self.code[idx_next:], ip=insn.next_ip))
                    break
                elif insn.mnemonic == Mnemonic.RET or \
                insn.mnemonic == Mnemonic.RETF or \
                insn.mnemonic == Mnemonic.HLT or \
                insn.mnemonic == Mnemonic.SYSCALL or \
                insn.mnemonic == Mnemonic.INT:
                    is_control_flow_end = True
                    bbs.append(bb)
                    bb = []
                    break
                elif insn.is_jmp_short_or_near:
                    is_control_flow_end = True
                    bbs.append(bb)
                    bb = []
                    insn.as_near_branch()
                    idx = insn.near_branch_target - self.base
                    targets.append(Decoder(self.bitness, self.code[idx:], ip=insn.near_branch_target))
                    break
                elif insn.is_jmp_far or insn.is_call_far or \
                insn.is_jmp_near_indirect or insn.is_call_near_indirect or \
                insn.is_jmp_far_indirect or insn.is_call_far_indirect:
                    is_control_flow_end = True
                    bbs.append(bb)
                    bb = []
                    break
            if not is_control_flow_end:
                bbs.append(bb)
                bb = []
            #except:
            #    continue
        print("[*] creating basicblocks")
        for bb in bbs:
            insn_end = bb[-1]
            insn_start = bb[0]
            idx_bb = insn_start.ip - self.base
            if insn_end.is_jcc_short_or_near or \
            insn_end.is_jkcc_short_or_near or \
            insn_end.is_call_near or \
            insn_end.is_loop or \
            insn_end.is_loopcc:
                idx_to_bb = {'jmp':insn.near_branch_target,'seq':insn.next_ip}
            elif insn_end.is_jmp_short_or_near:
                idx_to_bb = {'jmp':insn.near_branch_target,'seq':None}
            elif insn.is_jmp_far or insn.is_call_far or \
                insn.is_jmp_near_indirect or insn.is_call_near_indirect or \
                insn.is_jmp_far_indirect or insn.is_call_far_indirect or \
                insn.mnemonic == Mnemonic.HLT or \
                insn.mnemonic == Mnemonic.SYSCALL or \
                insn.mnemonic == Mnemonic.RET or \
                insn.mnemonic == Mnemonic.INT or \
                insn.mnemonic == Mnemonic.RETF:
                idx_to_bb = {'jmp':None,'seq':None}
            else:
                idx_to_bb = {'jmp':None,'seq':insn_end.next_ip}
            self.bbs_with_links[idx_bb] = {'bb':bb, 'idx_to_bb':idx_to_bb}
            self.remove_reps()
    def remove_rep_bbs(self,idx1,idx2):
        bb1 = self.bbs_with_links[idx1]
        bb2 = self.bbs_with_links[idx2]
        for i in range(len(bb1['bb'])):
            for j in range(len(bb2['bb'])):
                if bb1['bb'][i].ip == bb2['bb'][j].ip:
                    self.bbs_with_links.pop(idx2)
                    return True
        return False
    def remove_reps(self):
        idxs = sorted(list(self.bbs_with_links.keys()))
        bbs = []
        for idx1 in idxs: 
            for idx2 in idxs:
                if idx1 == idx2:
                    continue
                if self.remove_rep_bbs(idx1,idx2):
                    i = idxs.index(idx2)
                    idxs.pop(i)
    def print_bbs(self):
        idxs = sorted(list(self.bbs_with_links.keys()))
        for idx in idxs:
            bb = self.bbs_with_links[idx]
            print("BasicBlock %lx" % idx)
            for insn in bb['bb']:
                if insn.mnemonic == Mnemonic.DB:
                    continue
                disasm = self.formatter.format(insn)
                print(f"{insn.ip:016X} {disasm}")
    def build_bbs(self):
        idxs = sorted(list(self.bbs_with_links.keys()))
        mc = b''
        for idx in idxs:
            bb = self.bbs_with_links[idx]['bb']
            eb = BlockEncoder(64)
            eb.add_many(bb)
            mc += eb.encode(self.base)
        return mc
    def gen_reg64(self):
        regs64 = [
            Register.RAX,
            Register.RDX,
            Register.RBX,
            Register.RBP,
            Register.RSI,
            Register.RDI,
            Register.R8,
            Register.R9,
            Register.R10,
            Register.R11,
            Register.R12,
            Register.R13,
            Register.R14,
            Register.R15
        ]
        random.shuffle(regs64)
        return regs64[-1]
    def gen_reg32(self):
        regs32 = [
            Register.EAX,
            Register.EDX,
            Register.EBX,
            Register.EBP,
            Register.ESI,
            Register.EDI,
            Register.R8D,
            Register.R9D,
            Register.R10D,
            Register.R11D,
            Register.R12D,
            Register.R13D,
            Register.R14D,
            Register.R15D
        ]
        random.shuffle(regs32)
        return regs32[-1]
    def gen_reg16(self):
        regs16 = [
            Register.AX,
            Register.DX,
            Register.BX,
            Register.BP,
            Register.SI,
            Register.DI,
            Register.R8W,
            Register.R9W,
            Register.R10W,
            Register.R11W,
            Register.R12W,
            Register.R13W,
            Register.R14W,
            Register.R15W
        ]
        random.shuffle(regs16)
        return regs16[-1]
    def gen_reg8(self):
        regs8 = [
            Register.AL,
            Register.DL,
            Register.BL,
            Register.BPL,
            Register.DIL,
            Register.SIL,
            Register.R8L,
            Register.R9L,
            Register.R10L,
            Register.R11L,
            Register.R12L,
            Register.R13L,
            Register.R14L,
            Register.R15L,
        ]
        random.shuffle(regs8)
        return regs8[-1]
    #def gen_junk_0(self,start_ea):
    #def gen_junk_1(self,start_ea):
    #def gen_junk_2(self,start_ea):
    #def gen_junk_3(self,start_ea):
    def gen_junk_4(self,start_ea):
        insns = []
        reg1,reg2,reg3,reg4 = self.gen_reg64(),self.gen_reg64(),self.gen_reg64(),self.gen_reg64()
        while True:
            if reg1 == reg2:
                reg1 = self.gen_reg64()
            else:
                break
        while True:
            if reg2 == reg3:
                reg2 = self.gen_reg64()
            else:
                break
        while True:
            if reg3 == reg4:
                reg3 = self.gen_reg64()
            else:
                break
        while True:
            if reg4 == reg2:
                reg4 = self.gen_reg64()
            else:
                break
        while True:
            if reg1 == reg4:
                reg1 = self.gen_reg64()
            else:
                break
        init_insns = [
            Instruction.create_reg(Code.PUSH_R64,reg1),
            Instruction.create_reg(Code.PUSH_R64,reg2),
            Instruction.create_reg(Code.PUSH_R64,reg3),
            Instruction.create_reg(Code.PUSH_R64,reg4),
        ]
        random.shuffle(init_insns)
        init_insns[0].ip = start_ea
        insns.extend(init_insns)
        body = [
            Instruction.create_reg_i32(Code.ADD_RM64_IMM32,reg1,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.ADD_RM64_IMM32,reg2,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.ADD_RM64_IMM32,reg3,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.ADD_RM64_IMM32,reg4,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.SUB_RM64_IMM32,reg1,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.SUB_RM64_IMM32,reg2,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.SUB_RM64_IMM32,reg3,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.SUB_RM64_IMM32,reg4,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.OR_RM64_IMM32,reg1,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.OR_RM64_IMM32,reg2,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.OR_RM64_IMM32,reg3,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.OR_RM64_IMM32,reg4,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.AND_RM64_IMM32,reg1,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.AND_RM64_IMM32,reg2,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.AND_RM64_IMM32,reg3,randint(0,0x00ffffff)),
            Instruction.create_reg_i32(Code.AND_RM64_IMM32,reg4,randint(0,0x00ffffff)),
        ]
        random.shuffle(body)
        insns.extend(body)
        fini_insns = [
            Instruction.create_reg(Code.POP_R64,init_insns[3].op0_register),
            Instruction.create_reg(Code.POP_R64,init_insns[2].op0_register),
            Instruction.create_reg(Code.POP_R64,init_insns[1].op0_register),
            Instruction.create_reg(Code.POP_R64,init_insns[0].op0_register),
        ]
        insns.extend(fini_insns)
        ip = start_ea
        for i in range(len(insns)):
            insns[i].ip = ip
            e = Encoder(64)
            ip+=e.encode(insns[i],ip)
        return insns
    def gen_junk_5(self,start_ea):
        insns = []
        reg1,reg2,reg3 = self.gen_reg64(),self.gen_reg64(),self.gen_reg64()
        while True:
            if reg1 == reg2:
                reg1 = self.gen_reg64()
            else:
                break
        while True:
            if reg2 == reg3:
                reg2 = self.gen_reg64()
            else:
                break
        while True:
            if reg1 == reg3:
                reg1 = self.gen_reg64()
            else:
                break
        init_insns = [
            Instruction.create_reg(Code.PUSH_R64,reg1),
            Instruction.create_reg(Code.PUSH_R64,reg2),
            Instruction.create_reg(Code.PUSH_R64,reg3),
        ]
        random.shuffle(init_insns)
        init_insns[0].ip = start_ea
        insns.extend(init_insns)
        body = [
            Instruction.create_reg_reg(Code.XCHG_RM64_R64,reg1,reg2),
            Instruction.create_reg_reg(Code.XADD_RM64_R64,reg1,reg3),
            Instruction.create_reg_i32(Code.ROL_RM64_IMM8,reg3,randint(0,255)),
            Instruction.create_reg_reg(Code.XCHG_RM64_R64,reg3,reg2),
            Instruction.create_reg_i32(Code.ROR_RM64_IMM8,reg2,randint(0,255)),
            Instruction.create_reg_i32(Code.ROR_RM64_IMM8,reg1,randint(0,255)),
            Instruction.create_reg_i32(Code.ROL_RM64_IMM8,reg1,randint(0,255)),
            Instruction.create_reg_reg(Code.XADD_RM64_R64,reg2,reg1),
            Instruction.create_reg_reg(Code.XADD_RM64_R64,reg3,reg3),
            Instruction.create_reg(Code.BSWAP_R64,reg2),
            Instruction.create_reg(Code.BSWAP_R64,reg1),
            Instruction.create_reg_i32(Code.XOR_RM64_IMM32,reg3,randint(0x0,0x00ffffff)),
            Instruction.create_reg(Code.BSWAP_R64,reg3),
            Instruction.create_reg_i32(Code.XOR_RM64_IMM32,reg2,randint(0x0,0x00ffffff)),
            Instruction.create_reg_i32(Code.XOR_RM64_IMM32,reg1,randint(0x0,0x00ffffff)),
        ]
        random.shuffle(body)
        insns.extend(body)
        fini_insns = [
            Instruction.create_reg(Code.POP_R64,init_insns[2].op0_register),
            Instruction.create_reg(Code.POP_R64,init_insns[1].op0_register),
            Instruction.create_reg(Code.POP_R64,init_insns[0].op0_register),
        ]
        insns.extend(fini_insns)
        ip = start_ea
        for i in range(len(insns)):
            insns[i].ip = ip
            e = Encoder(64)
            ip+=e.encode(insns[i],ip) 
        return insns
    def gen_junk(self,count,start_ea):
        insns = []
        ip = start_ea
        for i in range(count):
            types = random.randint(4,5)
            #if types == 0:
            #    insns.extend(self.gen_junk_0(start_ea))
            #elif types == 1:
            #    insns.extend(self.gen_junk_1(start_ea))
            #elif types == 2:
            #    insns.extend(self.gen_junk_2(start_ea))
            #elif types == 3:
            #    insns.extend(self.gen_junk_3(start_ea))
            if types == 4:
                insns.extend(self.gen_junk_4(start_ea))
            elif types == 5:
                insns.extend(self.gen_junk_5(start_ea))
        return insns
    def gen_junk_bb(self, bb):
        inserts = random.randint(1,len(bb))
        for insert in range(inserts):
            point = random.randint(0,len(bb)-1)
            count_insns = random.randint(3,20)
            ip = bb[0].ip
            for i in self.gen_junk(count_insns,bb[point].ip):
                i.ip = ip
                e = Encoder(64)
                next_ip = e.encode(i,ip)
                ip+=next_ip
                bb.insert(point,i)
                point+=1
        return bb
    def correct_ips(self,bb):
        ip = bb[0].ip
        for i in range(len(bb)):
            bb[i].ip = ip
            e = Encoder(64)
            ip+=e.encode(bb[i],ip)
        return bb
    def get_next_ip(self,insn,ip):
        e = Encoder(64)
        return e.encode(insn,ip)
    def inject_smc(self,bb):
        smc_insns = []
        rol = lambda val, r_bits, max_bits: \
        (val << r_bits%max_bits) & (2**max_bits-1) | \
        ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
        # Rotate right: 0b1001 --> 0b1100
        ror = lambda val, r_bits, max_bits: \
        ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
        (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
        eb = BlockEncoder(64)
        eb.add_many(bb)
        mc = list(eb.encode(bb[0].ip))
        ops_count = randint(20,140)
        ops = []
        key = randint(0x10,127)
        for i in range(ops_count):
            op = randint(0,3)
            if op == 0: # xor
                for i in range(len(mc)):
                    mc[i] ^= key
                ops.append({'op':'xor'}) 
            elif op == 1: # not
                for i in range(len(mc)):
                    mc[i] ^= 0xff
                ops.append({'op':'not'})
            elif op == 2: # ror
                skey = randint(1,127)
                key = ror(key,skey,8)
                ops.append({'op':'ror','skey':skey})
            elif op == 3: # rol
                skey = randint(1,127)
                key = rol(key,skey,8)
                ops.append({'op':'rol','skey':skey})
        reg_key = self.gen_reg8()
        reg_smc_ea = self.gen_reg64()
        while True:
            if reg_key == Register.AL:
                reg_key64 = Register.RAX
            elif reg_key == Register.BL:
                reg_key64 = Register.RBX
            elif reg_key == Register.CL:
                reg_key64 = Register.RCX
            elif reg_key == Register.DL:
                reg_key64 = Register.RDX
            elif reg_key == Register.DIL:
                reg_key64 = Register.RDI
            elif reg_key == Register.SIL:
                reg_key64 = Register.RSI
            elif reg_key == Register.BPL:
                reg_key64 = Register.RBP
            elif reg_key == Register.R8L:
                reg_key64 = Register.R8
            elif reg_key == Register.R9L:
                reg_key64 = Register.R9
            elif reg_key == Register.R10L:
                reg_key64 = Register.R10
            elif reg_key == Register.R11L:
                reg_key64 = Register.R11
            elif reg_key == Register.R12L: 
                reg_key64 = Register.R12
            elif reg_key == Register.R13L:
                reg_key64 = Register.R13
            elif reg_key == Register.R14L:
                reg_key64 = Register.R14
            elif reg_key == Register.R15L:        
                reg_key64 = Register.R15
            if reg_smc_ea == reg_key64:
                reg_smc_ea = self.gen_reg64()
                reg_key    = self.gen_reg8()
            else:
                break
        ip = bb[0].ip
        smc_insns.append(Instruction.create_reg(Code.DEC_RM64,Register.RSP))
        smc_insns[-1].ip = ip
        ip += self.get_next_ip(smc_insns[-1],ip)
        smc_insns.append(Instruction.create_mem_reg(Code.MOV_RM8_R8,MemoryOperand(base=Register.RSP),reg_key))
        smc_insns[-1].ip = ip
        ip += self.get_next_ip(smc_insns[-1],ip)
        smc_insns.append(Instruction.create_reg_u64(Code.MOV_R8_IMM8,reg_key,key))
        smc_insns[-1].ip = ip
        ip += self.get_next_ip(smc_insns[-1],ip)
        smc_insns.append(Instruction.create_reg(Code.PUSH_R64,reg_smc_ea))
        smc_insns[-1].ip = ip
        ip += self.get_next_ip(smc_insns[-1],ip)
        smc_insns.append(Instruction.create_reg_mem(Code.LEA_R64_M,reg_smc_ea,MemoryOperand(Register.RIP,displ=1)))
        smc_insns[-1].ip = ip
        lea_idx = len(smc_insns)-1
        ip += self.get_next_ip(smc_insns[-1],ip)
        while len(ops) > 0:
            op = ops.pop()
            if op['op'] == 'xor':
                smc_insns.append(Instruction.create_reg(Code.PUSH_R64,Register.RCX))
                smc_insns[-1].ip = ip
                ip += self.get_next_ip(smc_insns[-1],ip)
                smc_insns.append(Instruction.create_reg_u64(Code.MOV_R64_IMM64,Register.RCX,len(mc)-1))
                smc_insns[-1].ip = ip
                ip += self.get_next_ip(smc_insns[-1],ip)
                smc_insns.append(Instruction.create_mem_reg(Code.XOR_RM8_R8,MemoryOperand(base=reg_smc_ea,index=Register.RCX),reg_key))
                smc_insns[-1].ip = ip
                ip += self.get_next_ip(smc_insns[-1],ip)
                #print(f'{hex(smc_insns[curr_i].ip)}: {smc_insns[curr_i]}')
                smc_insns.append(Instruction.create_branch(Code.LOOP_REL8_64_RCX,ip))
                smc_insns[-1].ip = ip
                smc_insns[-1].near_branch64 = smc_insns[-2].ip
                ip += self.get_next_ip(smc_insns[-1],ip)
                smc_insns.append(Instruction.create_mem_u32(Code.XOR_RM8_IMM8, MemoryOperand(base=reg_smc_ea,index=Register.RCX),0xff))
                smc_insns[-1].ip = ip
                #print(f'{hex(smc_insns[curr_i].ip)}: {smc_insns[curr_i]}')
                ip += self.get_next_ip(smc_insns[-1],ip)
                smc_insns.append(Instruction.create_reg(Code.POP_R64,Register.RCX))
                smc_insns[-1].ip = ip
                ip += self.get_next_ip(smc_insns[-1],ip)
            elif op['op'] == 'not':
                smc_insns.append(Instruction.create_reg(Code.PUSH_R64,Register.RCX))
                smc_insns[-1].ip = ip
                ip += self.get_next_ip(smc_insns[-1],ip)
                smc_insns.append(Instruction.create_reg_u64(Code.MOV_R64_IMM64,Register.RCX,len(mc)-1))
                smc_insns[-1].ip = ip
                ip += self.get_next_ip(smc_insns[-1],ip)
                smc_insns.append(Instruction.create_mem_u32(Code.XOR_RM8_IMM8, MemoryOperand(base=reg_smc_ea,index=Register.RCX),0xff))
                smc_insns[-1].ip = ip
                ip += self.get_next_ip(smc_insns[-1],ip)
                #print(f'{hex(smc_insns[curr_i].ip)}: {smc_insns[curr_i]}')
                smc_insns.append(Instruction.create_branch(Code.LOOP_REL8_64_RCX,ip))
                smc_insns[-1].ip = ip
                smc_insns[-1].near_branch64 = smc_insns[-2].ip
                ip += self.get_next_ip(smc_insns[-1],ip)
                smc_insns.append(Instruction.create_mem_u32(Code.XOR_RM8_IMM8, MemoryOperand(base=reg_smc_ea,index=Register.RCX),0xff))
                smc_insns[-1].ip = ip
                #print(f'{hex(smc_insns[curr_i].ip)}: {smc_insns[curr_i]}')
                ip += self.get_next_ip(smc_insns[-1],ip)
                smc_insns.append(Instruction.create_reg(Code.POP_R64,Register.RCX))
                smc_insns[-1].ip = ip
                ip += self.get_next_ip(smc_insns[-1],ip)
            elif op['op'] == 'ror':
                smc_insns.append(Instruction.create_reg_u32(Code.ROL_RM8_IMM8,reg_key,op['skey']))
                smc_insns[-1].ip = ip
                ip += self.get_next_ip(smc_insns[-1],ip)
            elif op['op'] == 'rol':
                smc_insns.append(Instruction.create_reg_u32(Code.ROR_RM8_IMM8,reg_key,op['skey']))
                smc_insns[-1].ip = ip
                ip += self.get_next_ip(smc_insns[-1],ip)
        smc_insns.append(Instruction.create_reg(Code.POP_R64,reg_smc_ea))
        smc_insns[-1].ip = ip
        ip += self.get_next_ip(smc_insns[-1],ip)
        smc_insns.append(Instruction.create_reg_mem(Code.MOV_R8_RM8,reg_key,MemoryOperand(base=Register.RSP)))
        smc_insns[-1].ip = ip
        ip += self.get_next_ip(smc_insns[-1],ip)
        smc_insns.append(Instruction.create_reg(Code.INC_RM64,Register.RSP))
        smc_insns[-1].ip = ip
        ip += self.get_next_ip(smc_insns[-1],ip)
        dbs = [Instruction.create_declare_byte_1(db) for db in mc]
        dbs[0].ip = ip
        smc_insns[lea_idx].memory_displacement = ip
        smc_insns.extend(dbs)
        return smc_insns
    def obfuscate_bbs(self):
        idxs = sorted(list(self.bbs_with_links.keys()))
        for idx in idxs:
            bb = self.bbs_with_links[idx]['bb']
            junked_bb = self.correct_ips(self.gen_junk_bb(bb))
            smc_bb = self.inject_smc(junked_bb)
            self.bbs_with_links[idx]['bb'] = smc_bb
        for idx in idxs:
            bb = self.bbs_with_links[idx]['bb']
            ip = bb[0].ip
            for i in range(len(bb)):
                bb[i].ip = ip
                e = Encoder(64)
                ip+=e.encode(bb[i],ip)
            self.bbs_with_links[idx]['bb'] = bb

def obfuscator_bin(code,base,start_analysis_ea):
    o = X64ObfuscatorLib(code, start_analysis_ea, base)
    o.load()
    print("[*] obfuscating bbs")
    o.obfuscate_bbs()
    #o.print_bbs()
    print('[*] rebuild bbs with splitting')
    encoded = o.build_bbs()
    print('[+] complete!')
    return encoded

#def pe_obfuscator(file_in,file_out):
#    import lief
#    file = lief.parse(file_in)
#    text_sec = file.get_section('.text')
#    text_sec_b = text_sec.content.tobytes()
#    base = text_sec.virtual_address + file.imagebase
#    entrypoint = file.entrypoint
#    idx = entrypoint - base
#    print('[*] obfuscating entrypoint')
#    obf_text = obfuscator_bin(text_sec_b,base,entrypoint)
#    file.patch_address(base,list(obf_text))
#    print('[*] saving binary to:',file_out)
#    file.write(file_out)

if __name__ == '__main__':
    #code = b"\x55\x48\x89\xE5\x48\x01\xD8\x48\x89\xE5\x5D\xC3"
    #code = b"\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9\x48\x31\xD2\x50\x68\x6E\x2F\x73\x68\x68\x2F\x2F\x62\x69\x48\x89\xEB\xB0\x0B\xCD\x80"
    code = b"\x48\xC7\xC0\x3C\x00\x00\x00\x30\xDB\x0F\x05"
    open('obf.bin','wb').write(obfuscator_bin(code,0,0))
    #from sys import argv
    #pe_obfuscator(argv[1],argv[2])