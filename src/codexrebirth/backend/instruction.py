
import re 


class InstructionSet(list):
    def __init__(self, insn_list):
        super().__init__()
        # set items to the list
        self.extend(insn_list)

    def __contains__(self, insn):
        for item in self:
            if re.match(item, insn):
                return True
        return False


# class used to store Unicorn operand and our own operand
class Instruction:
    def __init__(self, cinsn):
        # Une instruction peut avoir jusqu'à 3 opérandes
        self.cinsn = cinsn
        self.op1 = None
        self.op2 = None
        self.op3 = None
        self.v_op1 = None
        self.v_op2 = None
        self.v_op3 = None
        self.r_op1 = None
        self.r_op2 = None
        self.r_op3 = None
        self.v_op_result = None
        self.mem_access = None
        
    def _convert_operand(self, op):
        if isinstance(op, int):
            return hex(op)
        elif isinstance(op, str):
            try:
                return hex(int(op))
            except ValueError:
                return op

    def __repr__(self) -> str:
        res = f"{self.cinsn.mnemonic} {self.cinsn.op_str}\n"
        if self.v_op1:
            res += f"op1 = {self.v_op1}\n"
        elif self.op1:
            res += f"op1 = {self._convert_operand(self.r_op1)}\n" 
        if self.v_op2:
            res += f"op2 = {self.v_op2}\n"
        elif self.op2:
            res += f"op2 = {self._convert_operand(self.r_op2)}\n"
        if self.v_op3:
            res += f"op3 = {self.v_op3}\n"
        elif self.op3:
            res += f"op3 = {self._convert_operand(self.r_op3)}\n"
        if self.v_op_result:
            res += f"sym_result_id = {self.v_op_result.id}\n"
        if self.mem_access:
            res += f"mem_access = {self.mem_access}\n"
        return res

    def clone(self):
        clone = Instruction(self.cinsn)
        clone.op1 = self.op1
        clone.op2 = self.op2
        clone.op3 = self.op3
        clone.r_op1 = self.r_op1
        clone.r_op2 = self.r_op2
        clone.r_op3 = self.r_op3
        clone.mem_access = self.mem_access 
        clone.v_op1 = self.v_op1.clone() if self.v_op1 else None
        clone.v_op2 = self.v_op2.clone() if self.v_op2 else None
        clone.v_op3 = self.v_op3.clone() if self.v_op3 else None
        clone.v_op_result = self.v_op_result.clone() if self.v_op_result else None
        return clone
