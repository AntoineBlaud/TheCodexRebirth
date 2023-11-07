import re


class OperationSet(list):
    def __init__(self, operation_list):
        super().__init__()
        # set items to the list
        self.extend(operation_list)

    def __contains__(self, operation):
        for item in self:
            if re.match(item, operation):
                return True
        return False


# class used to store Unicorn operand and our own operand
class Operation:
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
        self.v_result = None
        self.mem_access = None
        self.cache_repr = None
        self.op_result = None
        self.eval_v_result = None

    def _convert_operand(self, op):
        if isinstance(op, int):
            return hex(op)
        elif isinstance(op, str):
            try:
                return hex(int(op))
            except ValueError:
                return op
        return op

    def operand_str(self, name, value):
        if value:
            return f"{name}={self._convert_operand(str(value))}\n"
        return ""

    def __ida__repr__(self):
        if self.cache_repr:
            return self.cache_repr

        result_op = self.operand_str("op1", self.r_op1)
        result_op += self.operand_str("op2", self.r_op2)
        result_op += self.operand_str("op3", self.r_op3)
        if self.mem_access:
            result_op += self.operand_str("mem_access", self.mem_access)
        if not self.eval_v_result:
            result_op += (
                self.operand_str("v_res", self.v_result)
                if self.v_result
                else self.operand_str("v_res", self.v_op1)
            )
        else:
            result_op += self.operand_str("v_res", self.v_result)
            result_op += self.operand_str("real_res", self.op_result)
            result_op += self.operand_str("eval_res", self.eval_v_result)
        result_str = result_op.replace("\n", ", ")
        self.cache_repr = result_str[:-2]
        return self.cache_repr

    def __repr__(self) -> str:
        result_str = f"{self.cinsn.mnemonic} {self.cinsn.op_str}\n"
        result_str += self.operand_str("mem_access", self.mem_access)
        result_op = self.operand_str("op1", self.r_op1)
        result_op += self.operand_str("op2", self.r_op2)
        result_op += self.operand_str("op3", self.r_op3)
        result_str += result_op
        result_str += self.operand_str("v_op1", self.v_op1)
        result_str += self.operand_str("v_op2", self.v_op2)
        result_str += self.operand_str("v_op3", self.v_op3)
        result_str = result_str[:-1]
        result_str += "\n"
        return result_str

    def clone(self):
        clone = Operation(self.cinsn)
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
        clone.v_result = self.v_result.clone() if self.v_result else None
        clone.op_result = self.op_result
        clone.eval_v_result = self.eval_v_result
        return clone
