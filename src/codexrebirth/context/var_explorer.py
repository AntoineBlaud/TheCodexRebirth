import idaapi
import idc
import idautils
import re

class VarExplorerTool:
    class RegVar:
        def __init__(self):
            self.reg = None
            self.name = None
            self.start = None
            self.end = None
    
        def clone(self):
            regvar = VarExplorerTool.RegVar()
            regvar.reg = self.reg
            regvar.name = self.name
            regvar.start = self.start
            regvar.end = self.end
            return regvar
        
    def __init__(self, log=False):
        self.regs_family = self.get_regs_mapping()
        self.stack_vars = self.get_stack_vars()
        self.defined_regs = {}
        self.log = log
        
    def update(self):
        self = VarExplorerTool()
        self.clear()
        self.propagate_operands()
        
        
    def log_msg(self, msg):
        if self.log:
            print(msg)

    def get_regs_mapping(self):
        return {
        "ah": ["rax", "eax", "ax", "ah", "al"],
        "al": ["rax", "eax", "ax", "ah", "al"],
        "ax": ["rax", "eax", "ax", "ah", "al"],
        "bh": ["rbx", "ebx", "bx", "bh", "bl"],
        "bl": ["rbx", "ebx", "bx", "bh", "bl"],
        "bp": ["rbp", "ebp", "bp", "bpl"],
        "bpl": ["rbp", "ebp", "bp", "bpl"],
        "bx": ["rbx", "ebx", "bx", "bh", "bl"],
        "ch": ["rcx", "ecx", "cx", "ch", "cl"],
        "cl": ["rcx", "ecx", "cx", "ch", "cl"],
        "cx": ["rcx", "ecx", "cx", "ch", "cl"],
        "dh": ["rdx", "edx", "dx", "dh", "dl"],
        "di": ["rdi", "edi", "di", "dil"],
        "dil": ["rdi", "edi", "di", "dil"],
        "dl": ["rdx", "edx", "dx", "dh", "dl"],
        "dx": ["rdx", "edx", "dx", "dh", "dl"],
        "eax": ["rax", "eax", "ax", "ah", "al"],
        "ebp": ["rbp", "ebp", "bp", "bpl"],
        "ebx": ["rbx", "ebx", "bx", "bh", "bl"],
        "ecx": ["rcx", "ecx", "cx", "ch", "cl"],
        "edi": ["rdi", "edi", "di", "dil"],
        "edx": ["rdx", "edx", "dx", "dh", "dl"],
        "esi": ["rsi", "esi", "si", "sil"],
        "r10": ["r10", "r10d", "r10w", "r10b"],
        "r10b": ["r10", "r10d", "r10w", "r10b"],
        "r10d": ["r10", "r10d", "r10w", "r10b"],
        "r10w": ["r10", "r10d", "r10w", "r10b"],
        "r11": ["r11", "r11d", "r11w", "r11b"],
        "r11b": ["r11", "r11d", "r11w", "r11b"],
        "r11d": ["r11", "r11d", "r11w", "r11b"],
        "r11w": ["r11", "r11d", "r11w", "r11b"],
        "r12": ["r12", "r12d", "r12w", "r12b"],
        "r12b": ["r12", "r12d", "r12w", "r12b"],
        "r12d": ["r12", "r12d", "r12w", "r12b"],
        "r12w": ["r12", "r12d", "r12w", "r12b"],
        "r13": ["r13", "r13d", "r13w", "r13b"],
        "r13b": ["r13", "r13d", "r13w", "r13b"],
        "r13d": ["r13", "r13d", "r13w", "r13b"],
        "r13w": ["r13", "r13d", "r13w", "r13b"],
        "r14": ["r14", "r14d", "r14w", "r14b"],
        "r14b": ["r14", "r14d", "r14w", "r14b"],
        "r14d": ["r14", "r14d", "r14w", "r14b"],
        "r14w": ["r14", "r14d", "r14w", "r14b"],
        "r15": ["r15", "r15d", "r15w", "r15b"],
        "r15b": ["r15", "r15d", "r15w", "r15b"],
        "r15d": ["r15", "r15d", "r15w", "r15b"],
        "r15w": ["r15", "r15d", "r15w", "r15b"],
        "r8": ["r8", "r8d", "r8w", "r8b"],
        "r8b": ["r8", "r8d", "r8w", "r8b"],
        "r8d": ["r8", "r8d", "r8w", "r8b"],
        "r8w": ["r8", "r8d", "r8w", "r8b"],
        "r9": ["r9", "r9d", "r9w", "r9b"],
        "r9b": ["r9", "r9d", "r9w", "r9b"],
        "r9d": ["r9", "r9d", "r9w", "r9b"],
        "r9w": ["r9", "r9d", "r9w", "r9b"],
        "rax": ["rax", "eax", "ax", "ah", "al"],
        "rbp": ["rbp", "ebp", "bp", "bpl"],
        "rbx": ["rbx", "ebx", "bx", "bh", "bl"],
        "rcx": ["rcx", "ecx", "cx", "ch", "cl"],
        "rdi": ["rdi", "edi", "di", "dil"],
        "rdx": ["rdx", "edx", "dx", "dh", "dl"],
        "rsi": ["rsi", "esi", "si", "sil"],
        "si": ["rsi", "esi", "si", "sil"],
        "sil": ["rsi", "esi", "si", "sil"],
    }
    
    
    def read_reg_family(self, reg_used):
        if reg_used in self.regs_family:
            return [reg_brother for reg_brother in self.regs_family[reg_used] if reg_brother in self.regs_family ]
        return []

    def get_stack_vars(self):
        func = idaapi.get_func(idc.here())
        frame = idaapi.get_frame(func)
        stack_vars = {}
        if frame is None:
            print("No frame information available for the function.")
            return {}
        for offset in range(0x2000):
            var = idc.get_member_name(frame.id, offset)
            if var is not None:
                stack_vars[var] = -1
        return stack_vars
    
    
    def get_func_instructions(self, func):
        flow_chart = idaapi.FlowChart(func)
        for block in flow_chart:
            for addr in idautils.Heads(block.start_ea, block.end_ea):
                yield addr, idc.GetDisasm(addr)
                
                
    def remove_comments(self, instruction):
        return instruction.split(';')[0] if ';' in instruction else instruction
                
    
    def disassemble_function_blocks(self, ea):
        func = idaapi.get_func(ea)
        instructions = []
        if not func:
            print("Function not found at 0x{:X}".format(ea))
        else:
            for addr, instruction in self.get_func_instructions(func):
                instruction = self.remove_comments(instruction)
                instructions.append((addr, instruction))
        return instructions

    def set_reg_name(self, start, end, reg, name):
        func = idaapi.get_func(idc.here())
        if idaapi.find_regvar(func, start, end, reg, name):
            idaapi.del_regvar(func, start, end, reg)
        self.log_msg(f"set_reg_name {hex(start)} {hex(end)} {reg} {name}")
        idaapi.add_regvar(func, start, end, reg, name, f'{reg} = {name}')
        
    def instantiate(self, addr, inst, reg):
        regvar = VarExplorerTool.RegVar()
        regvar.reg = reg
        regvar.name = f"{reg}_{self.find_stack_vars(inst)}"
        regvar.start = addr
        regvar.end = addr + 1
        if "None" in regvar.name:
            return None
        self.set_reg_name(regvar.start, regvar.end, regvar.reg, regvar.name)
        return regvar

    def is_mov_from_mem(self, instruction):
        return self.is_mov(instruction) and instruction.endswith(']')

    def is_mov_into_mem(self, instruction):
        return self.is_mov(instruction) and instruction.split(',')[0].endswith(']')

    def is_mov(self, instruction):
        return any(keyword in instruction for keyword in ('mov', 'lea'))

    def find_stack_vars(self, instruction):
        return next((var for var in self.stack_vars if var in instruction), None)

    def find_reg_first_op(self, instruction):
        instruction = instruction.split(',')[0]
        return next((reg_dependent for reg_used in self.regs_family if reg_used in instruction
                    for reg_dependent in self.read_reg_family(reg_used) if reg_dependent in instruction), None)


    def find_reg_first_op(self, instruction):
        instruction = instruction.split(',')[0]
        for reg_used in self.regs_family:
            if reg_used in instruction:
                for reg_dependent in self.read_reg_family(reg_used):
                    if reg_dependent in instruction:
                        return reg_dependent

    def find_regs_mov_inst(self, instruction):
        if not self.is_mov(instruction):
            return []

        try:
            operands = ' '.join(instruction.split(" ")[1:])
            operands = operands.replace(' ', '').replace('lea', '')
            return operands.split(',')
        except:
            return []

    def find_regs_any_inst(self, instruction):
        regs_used = [reg for reg in self.regs_family if reg in instruction]
        reg_used_groupped = {}
        
        # for reg detected, check if any of the family is used
        # There is a priority in the family, so we can group them
        for reg_used in regs_used:
            for reg_brother in self.read_reg_family(reg_used):
                if reg_brother in instruction:
                    reg_used_groupped[reg_brother] = None
                    break
                
        return list(reg_used_groupped.keys())
    
    
    def clear(self):
        ea = idc.here()
        func = idaapi.get_func(ea)
        if func:
            for reg in self.regs_family:
                # for each 
                for addr, _ in self.get_func_instructions(func):
                    idaapi.del_regvar(func, addr, addr + 1, reg)


    def propagate_operands(self):
        ea = idc.here()
        instructions = self.disassemble_function_blocks(ea)

        for addr, inst in instructions:
            
            # if we find a call, we reset the defined registers
            if "call" in inst:
                self.defined_regs = {}
                continue
            
            # if a value read from memory is used, we instantiate a new variable
            if self.is_mov_from_mem(inst):
                reg = self.find_reg_first_op(inst)
                if reg:
                    regvar = self.instantiate(addr, inst, reg)
                    if regvar:
                        self.defined_regs[reg] = regvar
            
            # else destroy the RegVar if the first instruction operand
            elif self.is_mov(inst):
                    reg_used = self.find_reg_first_op(inst)
                    for reg_brother in self.read_reg_family(reg_used):
                        if reg_brother in self.defined_regs:
                            del self.defined_regs[reg_brother]

            # for each register used in the instruction, we propagate the name
            # of the variable to the current address
            for reg_used in self.find_regs_any_inst(inst):
                regvar = None
                # for one register used, we have to update all his family
                for reg_brother in self.read_reg_family(reg_used):
                    if reg_brother in self.defined_regs:
                        regvar = self.defined_regs[reg_brother]
                        regvar.end = addr + 1
                        if reg_brother == reg_used:
                            var_name = regvar.name.replace(regvar.reg, reg_used)
                            self.set_reg_name(regvar.start, regvar.end, reg_brother, var_name)


            # assign a new variable to the register if it is a mov instruction between registers
            if not self.is_mov_into_mem(inst) and len(self.find_regs_mov_inst(inst)) == 2:
                regs = self.find_regs_mov_inst(inst)
                inst = inst.split(',')
                reg1, reg2 = regs
                for reg_brother in self.read_reg_family(reg2):
                    if reg_brother in self.defined_regs:
                        regvar = self.defined_regs[reg_brother].clone()
                        self.defined_regs[reg1] = regvar
                        regvar.reg = reg1
                        regvar.start = addr + 1
                        regvar.end = addr + 1
                        regvar.name = regvar.name.replace(reg_brother, reg1)
                        self.set_reg_name(self.defined_regs[reg1].start, self.defined_regs[reg1].end, reg1, self.defined_regs[reg1].name)




