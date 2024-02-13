#########################################################
# Author: @d0raken - Antoine Blaud
# Date: 2023-09-18
# CodexRebirth is a symbolic execution engine based on Qiling
# It is used to emulate a binary and to extract the symbolic execution trace
#########################################################


from capstone.x86_const import X86_OP_MEM, X86_OP_REG, X86_OP_IMM
from capstone.arm_const import ARM_OP_MEM, ARM_OP_REG, ARM_OP_IMM
from tenet.trace.arch import ArchAMD64, ArchX86, ArchARM, ArchARM64
from capstone import *
from unicorn import unicorn
from qiling.const import QL_ARCH
from keystone import *
from superglobals import *
from tenet.util.log import logging_started, start_logging

from tenet.util.counter import *
from tenet.util.common import *
from tenet.util.exceptions import *
import logging

# allow to register functions called during eval
# DO NOT REMOVE
from tenet.util.bitwise_math import *

from .operation import (
    Operation,
)
from .trace_saver import Trace

from .values_container import SymValue, RealValue, IndirectSymValue, SymRegister, SymMemory

from .datastore import DataStoreManager

from z3 import set_option
import re

from .debug_profiler import profile

__all__ = ["DebugLevel", "Runner"]

# Set z3 options
set_option(rational_to_decimal=True)
set_option(
    max_args=0xFFFF,
    max_lines=0xFFFF,
    max_depth=0xFFFF,
    max_visited=0xFFFF,
)


class DebugLevel:
    ERROR = 0
    INFO = 1
    DEBUG = 2


BAD_OPERANDS_X86_64 = [".*pl", ".*il", ".*z", ".*h", ".*w"]
ID_COUNTER = alt_count()
VAR_COUNTER = alt_count()


def get_reg_name(cs, reg):
    name = cs.reg_name(reg)
    if isinstance(name ,str):
        return name.upper()
    return None


if not logging_started():
    logger = start_logging()
    
logger = logging.getLogger("Tenet.Taint_Engines.Core")
logger.setLevel(logging.DEBUG)

def create_sym_register_factory():
    """
    Create a dictionary of symbolic registers and their parts.
    Used also to link a register part to its parent register.
    """
    global SYM_REGISTER_FACTORY
    import tenet.taint_engine.arch.x86 as x86
    SYM_REGISTER_FACTORY = x86.create_sym_register_factory()
    return SYM_REGISTER_FACTORY

def get_parent_register(register_name, arch_size):
    import tenet.taint_engine.arch.x86 as x86
    return x86.get_parent_register(register_name, arch_size)

def check_memory_access(insn):
    # lea instruction is not a memory access
    if insn.mnemonic == "lea":
        return False

    for op in insn.operands:
        if op.type in [X86_OP_MEM, ARM_OP_MEM]:
            return True
    return False


class VariableStates(dict):
    """
    This class is a wrapper around a dictionary that stores symbolic tainted variables.
    Symbolic variables are instance of SymValue or RealValue.
    """

    def __init__(self):
        super().__init__()

    def __contains__(self, key_object: object):
        # Check if a key_object (possibly processed) exists in the dictionary
        key_object = create_name_from_address(key_object)
        if isinstance(key_object, str):
            key_object = key_object.upper()
        return super().__contains__(key_object)

    def __setitem__(self, key_object, value):
        # Set an item in the dictionary after processing the key
        key_object = create_name_from_address(key_object)
        if isinstance(key_object, str):
            key_object = key_object.upper()
        super().__setitem__(key_object, value)

    def __getitem__(self, key_object):
        # Get an item from the dictionary after processing the key
        key_object = create_name_from_address(key_object)
        if isinstance(key_object, str):
            key_object = key_object.upper()
        return super().__getitem__(key_object)
    
    def __delitem__(self, key_object):
        if isinstance(key_object, str):
            key_object = key_object.upper()
        return super().__delitem__(key_object)
    
    def update(self, key, value):
        global SYM_REGISTER_FACTORY
        _object = self[key]
        # update depend register parts 
        # ex: rax -> [rax, eax, ax, ah, al]
        if isinstance(_object, SymRegister):
            for reg_dep in SYM_REGISTER_FACTORY[key]:
                res = reg_dep._update(value)
                # update() returns a value if the object change class
                if res:
                    self[reg_dep.name] = res
                    
        else:
            res = _object.update(value)
            # update() returns a value if the object change class
            if res:
                self[key] = res
                
        # return the updated object
        return self[key]
   
            
        

    def create_sym_reg(self, name):
        # we reset the register to a new symbolic value
        # each register parts are reset to a new symbolic value
        global SYM_REGISTER_FACTORY, logger
        # Create a new symbolic register and propagate the value to its parts
        # (e.g., 'ah' to ['rax', 'eax', 'ax', 'ah', 'al'])
        logger.debug(f"Create symbolic register {name}")
        for reg in SYM_REGISTER_FACTORY[name]:
            self[reg.name] = reg.reset()
        return self[name]

    def create_sym_mem(self, address, value):
        global ID_COUNTER, logger
        id = ID_COUNTER.value
        # Create a new symbolic memory object
        name = create_name_from_address(address)
        self[name] = SymMemory(name, value)
        logger.debug(f"Create symbolic memory {name} with value {value}")
        return self[name]

    def del_sym_var(self, name):
        # Delete a symbolic variable, handling register parts and
        # individual variables
        global SYM_REGISTER_FACTORY, logger
        name = create_name_from_address(name)

        logger.debug(f"Delete symbolic variable {name}")

        if name not in self:
            return

        if name in SYM_REGISTER_FACTORY:
            for reg in SYM_REGISTER_FACTORY[name]:
                if reg.name in self:
                    del self[reg.name]
        else:
            del self[name]

    def __repr__(self) -> str:
        res = ""
        for key, value in self.items():
            res += f"{key} = {value}\n"
        return res

    def clone(self):
        clone = VariableStates()
        for key, value in self.items():
            clone[key] = value.clone()
        return clone


class OperationX86_64:
    """
    A class for performing a symbolic operations on x86-64 machine code.
    """

    def __init__(self, config, cs, engine, operation, mem_access, symbolic_taint_store):
        self.config = config
        self.cs = cs
        self.operation = operation
        self.mem_access = mem_access
        self.symbolic_taint_store = symbolic_taint_store
        self.engine = engine
        self.tainted_var_name = self.find_var_name_tainted(operation, mem_access)

    def find_var_name_tainted(self, operation: Operation, mem_access: int):
        if not operation.op1:
            return None
        if operation.op1.type == X86_OP_MEM:
            return mem_access
        else:
            return get_reg_name(self.cs, operation.op1.reg)

    def _add(self, operation, symbolic_taint_store):
        return symbolic_taint_store.update(self.tainted_var_name, operation.v_op1 + operation.v_op2)

    def _imul(self, operation, symbolic_taint_store):
        if operation.v_op3 is not None:
            return symbolic_taint_store.update(self.tainted_var_name, operation.v_op2 * operation.v_op3)
        if operation.v_op2 is not None:
            return symbolic_taint_store.update(self.tainted_var_name, operation.v_op1 * operation.v_op2)
        else:
            if "rax" in symbolic_taint_store:
                return symbolic_taint_store.update("rax", (symbolic_taint_store["rax"] * operation.v_op1))

    def _sub(self, operation, symbolic_taint_store):
        return symbolic_taint_store.update(self.tainted_var_name, operation.v_op1 - operation.v_op2)

    def _xor(self, operation, symbolic_taint_store):
        return symbolic_taint_store.update(self.tainted_var_name, operation.v_op1 ^ operation.v_op2)

    def _and(self, operation, symbolic_taint_store):
        return symbolic_taint_store.update(self.tainted_var_name, operation.v_op1 & operation.v_op2)

    def _or(self, operation, symbolic_taint_store):
        return symbolic_taint_store.update(self.tainted_var_name, operation.v_op1 | operation.v_op2)

    def _shl(self, operation, symbolic_taint_store):
        destination = operation.v_op1
        bsize = self.config["BINARY_ARCH_SIZE"]
        if operation.v_op3 is not None:
            source = operation.v_op2
            count = operation.v_op3.value % bsize
            shifted_bits = destination << RealValue(count)
            shifted_bits |= source >> RealValue(bsize - count)
        else:
            count = operation.v_op2
            shifted_bits = destination << count
        return symbolic_taint_store.update(self.tainted_var_name, shifted_bits)

    def _shr(self, operation, symbolic_taint_store):
        destination = operation.v_op1
        bsize = self.config["BINARY_ARCH_SIZE"]
        if operation.v_op3 is not None:
            source = operation.v_op2
            count = operation.v_op3.value % bsize
            shifted_bits = destination >> RealValue(count)
            shifted_bits |= source << RealValue(bsize - count)
        else:
            count = operation.v_op2
            shifted_bits = destination >> count
        return symbolic_taint_store.update(self.tainted_var_name, shifted_bits)

    def _ror(self, operation, symbolic_taint_store):
        return symbolic_taint_store.update(self.tainted_var_name, operation.v_op1.ror(operation.v_op2))

    def _rol(self, operation, symbolic_taint_store):
        return symbolic_taint_store.update(self.tainted_var_name, operation.v_op1.rol(operation.v_op2))

    def _mul(self, operation, symbolic_taint_store):
        return symbolic_taint_store.update("rax", symbolic_taint_store[self.tainted_var_name] * operation.v_op1)

    def _not(self, operation, symbolic_taint_store):
        return symbolic_taint_store.update(self.tainted_var_name, operation.v_op1._not())

    def _cdq(self, operation, symbolic_taint_store):
        symbolic_taint_store.del_sym_var("rdx")
        return None

    def _push(self, operation, symbolic_taint_store):
        stack_pointer = self.engine.get_stack_pointer()
        symbolic_taint_store.create_sym_mem(stack_pointer, 0)
        symbolic_taint_store.update(stack_pointer, operation.v_op1)
        return symbolic_taint_store[stack_pointer]

    def _pop(self, operation, symbolic_taint_store):
        stack_pointer = self.engine.get_stack_pointer()
        reg = get_reg_name(self.cs, operation.op1.reg)
        # Delete the symbolic register
        if not reg in symbolic_taint_store:
            symbolic_taint_store.create_sym_reg(reg)

        if stack_pointer in symbolic_taint_store:
            symbolic_taint_store.update(reg, symbolic_taint_store[stack_pointer])
            symbolic_taint_store.del_sym_var(stack_pointer)
        else:
            value = self.engine.read_memory_int(stack_pointer)
            symbolic_taint_store.update(reg, symbolic_taint_store.create_sym_mem(stack_pointer, value))

        return symbolic_taint_store[reg]

    def _mov(self, operation, symbolic_taint_store, mem_access):
        # instanciate a new symbolic register if needed
        # if condition is not met, then delete the symbolic register
        if operation.op1.type == X86_OP_REG:
            regname = get_reg_name(self.cs, operation.op1.reg)
            symbolic_taint_store.update(regname, operation.v_op2)
            return symbolic_taint_store[regname]

        elif operation.op1.type == X86_OP_MEM:
            symbolic_taint_store.update(mem_access, operation.v_op2)
            return symbolic_taint_store[mem_access]

        raise Exception(f"Operation {operation.cinsn.mnemonic} not supported")

    def _lea(self, operation, symbolic_taint_store, mem_access):
        global ID_COUNTER
        regname = get_reg_name(self.cs, operation.op1.reg)
        # found mem_access to next 4 bytes
        mem_access = mem_access + (mem_access % 4)
        symbolic_taint_store.update(regname, RealValue(mem_access))
        id = ID_COUNTER.value
        symbolic_taint_store[regname].id = set([id])
        return symbolic_taint_store[regname]

    def process(self):
        if self.tainted_var_name not in self.symbolic_taint_store:
            return None
        cinsn = self.operation.cinsn

        if "rep" in cinsn.mnemonic:
            return None
        if "mov" in cinsn.mnemonic:
            return self._mov(self.operation, self.symbolic_taint_store, self.mem_access)
        elif "lea" in cinsn.mnemonic:
            return self._lea(self.operation, self.symbolic_taint_store, self.mem_access)
        elif cinsn.mnemonic.startswith("add"):
            return self._add(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("imul"):
            return self._imul(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("sub"):
            return self._sub(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("xor"):
            return self._xor(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("and"):
            return self._and(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("or"):
            return self._or(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("shl"):
            return self._shl(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("shr") or cinsn.mnemonic.startswith("sar"):
            return self._shr(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("ror"):
            return self._ror(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("rol"):
            return self._rol(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("mul"):
            return self._mul(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("not"):
            return self._not(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("push"):
            return self._push(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("pop"):
            return self._pop(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("cdq"):
            return self._cdq(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("test") or cinsn.mnemonic.startswith("cmp"):
            return self.operation.v_op1
        elif cinsn.mnemonic.startswith("call") or cinsn.mnemonic.startswith("j"):
            return self.operation.v_op1
        else:
            return None


class OperationEngine:
    """
    A class for performing symbolic execution on x86-64 machine code using Qiling.

    Args:
        engine (Qiling): An instance of the Qiling emulator.
    """

    def __init__(self, engine, arch, cs, ks):
        # Store the Qiling instance and configure Capstone disassembler and Keystone assembler
        self.engine = engine
        self.arch = arch
        self.cs = cs
        self.ks = ks
        if isinstance(arch, ArchAMD64) or isinstance(arch, ArchX86):
            self.op_reg_type = X86_OP_REG
            self.op_imm_type = X86_OP_IMM
            self.op_mem_type = X86_OP_MEM
        elif isinstance(arch, ArchARM) or isinstance(arch, ArchARM64):
            self.op_reg_type = ARM_OP_REG
            self.op_imm_type = ARM_OP_IMM
            self.op_mem_type = ARM_OP_MEM
        else:
            raise Exception("Unsupported architecture")
        # Initialize variables for tracking the last executed instruction
        self.last_instruction_executed = None
        self.is_last_instruction_symbolic = False
        # Set the debug level and symbolic execution check interval
        self.config = None

    def set_config(self, config):
        self.config = config

    def discover_indirect_access(self, op, mem_access, symbolic_taint_store: VariableStates):
        # Create an IndirectSymValue object from mem_access instruction

        def fetch_symbolic_register(reg_name):
            # Helper function to fetch a symbolic register from symbolic_taint_store
            if reg_name in symbolic_taint_store and isinstance(symbolic_taint_store[reg_name], SymValue):
                return IndirectSymValue(symbolic_taint_store[reg_name])

        if op.mem.base != 0:
            reg_name_base = get_reg_name(self.cs, op.mem.base)
            return fetch_symbolic_register(reg_name_base)

        if op.mem.index != 0:
            reg_name_index = get_reg_name(self.cs, op.mem.index)
            return fetch_symbolic_register(reg_name_index)

        return None

    def parse_operation_operands(self, cinsn, mem_access: int, symbolic_taint_store: VariableStates):
        global SYM_REGISTER_FACTORY, logger
        # Parse the operands of the instruction, create symbolic values if needed, and return the Operation object
        operation = Operation(cinsn)
        operation.mem_access = mem_access

        if len(operation.cinsn.operands) == 0:
            return operation

        # Check if the operand is a symbolic memory access and create a symbolic value
        for i, op in enumerate(cinsn.operands):
            if op.type == self.op_mem_type and mem_access not in symbolic_taint_store:
                sym_access = self.discover_indirect_access(op, mem_access, symbolic_taint_store)
                if isinstance(sym_access, IndirectSymValue):
                    logger.debug(f"Found a indirect sym memory")
                    # set the mem_access to the indirect sym value.
                    # The indirect sym value is equal to the value of the register + the displacement
                    symbolic_taint_store[mem_access] = sym_access
        #
        # Process the tainted data of the operands
        #
        for i in range(min(len(cinsn.operands), 3)):
            operand = cinsn.operands[i]
            setattr(operation, f"op{i+1}", operand)
            # Process REG operands
            if operand.type == self.op_reg_type:
                regname = get_reg_name(self.cs, operand.reg)
                if regname not in symbolic_taint_store and regname in SYM_REGISTER_FACTORY:
                    symbolic_taint_store.create_sym_reg(regname)
                if regname in symbolic_taint_store:
                    setattr(operation, f"v_op{i+1}", symbolic_taint_store[regname])
                else:
                    setattr(
                        operation,
                        f"v_op{i+1}",
                        RealValue(self.engine.read_reg(regname.upper())),
                    )
            # Process IMM operands
            elif operand.type == self.op_imm_type:
                setattr(operation, f"v_op{i+1}", RealValue(operand.imm))

            # Process MEM operands
            elif operand.type == self.op_mem_type:
                if mem_access not in symbolic_taint_store and self.engine.is_mapped(mem_access):
                    symbolic_taint_store.create_sym_mem(mem_access, self.engine.read_memory_int(mem_access))
                if mem_access in symbolic_taint_store:
                    setattr(operation, f"v_op{i+1}", symbolic_taint_store[mem_access])
                else:
                    setattr(operation, f"v_op{i+1}", RealValue(0))

            assert getattr(operation, f"v_op{i+1}") is not None

        #
        # Parse real values of the operands
        #
        for i, op in enumerate(cinsn.operands):
            if op.type == self.op_reg_type:
                regname = get_reg_name(self.cs, op.reg)
                reg_value = self.engine.read_reg(regname.upper())
                setattr(operation, f"r_op{i + 1}", reg_value)

            elif op.type == self.op_mem_type and self.engine.is_mapped(mem_access):
                mem_value = self.engine.read_memory_int(mem_access)
                setattr(operation, f"r_op{i + 1}", hex(mem_value))

        return operation

    def make_var_substitutions(self, symbolic_taint_store: VariableStates, tainted_var_name: str):
        # we do not fetch from global config because it is to slow
        global VAR_COUNTER

        tainted_var_value = symbolic_taint_store.get(tainted_var_name, None)
        if not isinstance(tainted_var_value, SymValue):
            return

        var_size = z3_ast_size(tainted_var_value.value)
        # count sub variables inside the value
        sub_var_count = str(tainted_var_value).count("VAR_")
        # if not, then we didn't updated yet, so we create a new varname and assign it to the tainted_var_value
        if var_size > self.config["MAX_VAR_OPERANDS"] * (sub_var_count + 1):
            new_var = f"VAR_{next(VAR_COUNTER):06d}"
            new_value = SymValue(new_var)
            new_value.id = set(tainted_var_value.id)
            symbolic_taint_store[new_var] = tainted_var_value.clone()
            symbolic_taint_store.update(tainted_var_name, new_value)
            logger.info(f"Substituting {symbolic_taint_store[new_var]} to {new_var}")

    def compute_mem_access(self, cinsn):
        mem_access = 0
        try:
            for op in cinsn.operands:
                if op.type == self.op_mem_type:
                    mem_access += self.engine.read_reg(get_reg_name(self.cs, op.mem.base)) if op.mem.base != 0 else 0
                    mem_access += self.engine.read_reg(get_reg_name(self.cs, op.mem.index)) if op.mem.index != 0 else 0
                    mem_access += op.mem.disp
                    mem_access *= op.mem.scale if op.mem.scale > 1 else 1

        except Exception as e:
            raise e
        return mem_access

    def evaluate_instruction(self, symbolic_taint_store: VariableStates):
        global logger
        print("-"*40)
        if self.config is None:
            raise Exception("Config not set")

        # Get the current instruction
        cinsn = self.engine.get_currrent_instruction_disass()
        cinsn_addr = self.engine.get_ea()
        # Check if the instruction is the same as the last one executed
        if cinsn_addr == self.last_instruction_executed:
            logger.debug(f"Instruction {hex(cinsn_addr)} already executed\n")
            return None

        # check if the operands are not supported
        for bad_op_pattern in self.config["BAD_OPERANDS"]:
            if re.match(bad_op_pattern, cinsn.op_str):
                logger.debug(f"Bad operand: {hex(cinsn_addr)} {cinsn.op_str}, the result operation may be wrong")
                return None

        # mem_access can be calculated from cinsn of directly
        # read base, index, disp and scale from cinsn operands
        mem_access = self.compute_mem_access(cinsn)

        # store the last instruction executed
        self.last_instruction_executed = cinsn_addr
        self.last_mem_access = mem_access

        # Parse operands do a lot of things, like creating symbolic values, fetching values from memory
        # All the results are stored in the Operation object (v_op1, v_op2, v_op3)
        operation = self.parse_operation_operands(cinsn, mem_access, symbolic_taint_store)
        # Compute the result of the operation
        if isinstance(self.arch, ArchAMD64) or isinstance(self.arch, ArchX86):
            op_engine = OperationX86_64(
                self.config,
                self.cs,
                self.engine,
                operation,
                mem_access,
                symbolic_taint_store,
            )
        else:
            raise Exception("Unsupported architecture")
        operation.v_result = op_engine.process()
        print(hex(cinsn_addr), operation)
        # Update variables in symbolic_taint_store
        self.make_var_substitutions(symbolic_taint_store, op_engine.tainted_var_name)
        return operation.clone()


class Runner:
    def __init__(self, engine, arch, cs, ks, *args):
        # Set the debug level and create a VariableStates instance
        self.arch = arch
        self.cs = cs
        self.ks = ks
        # only for debugging
        self.symbolic_check = False
        self.symbolic_taint_store = VariableStates()
        # Initialize start and end addresses for emulation
        self.trace_records = Trace()
        self.operation_executed_count = ID_COUNTER
        self.registers_state = DataStoreManager()
        self.memory_state = DataStoreManager()
        # instantiate the engine
        self.engine = engine
        # Create an instance of the CodexOperationEngine
        self.operation_engine = OperationEngine(self.engine, self.arch, self.cs, self.ks, *args)
        self.emulation_time = 0
        

        self.CONFIG = {
            "BINARY_ARCH_SIZE": None,
            "BINARY_MAX_MASK": None,
            "MAX_VAR_OPERANDS": 8,
            "BAD_OPERANDS": None,
            "CS_UC_REGS": None,
            "TRACE_RECORDS": self.trace_records,
            "SYM_REGISTER_FACTORY": None,
            "ID_COUNTER": ID_COUNTER,
            "IS_INITIALIZED": False,
        }

    def get_current_pc(self):
        return self.engine.get_ea()
    
    def register_operations(self, operation: Operation):
        idx = self.operation_executed_count.value
        if operation is None:
            cinsn = self.engine.get_currrent_instruction_disass()
            operation = Operation(cinsn)

        last_trace = self.trace_records.get_last_entry()
        last_operation = last_trace.operation if last_trace else None

        # Register the current and last instruction register and memory changes
        self.register_execution_state(operation, last_operation)

        if self.symbolic_check:
            # first evaluate the current symbolic state (registers, memory and intermediate variables)
            self.evaluate_current_symbolic_state(operation)
            # make the last evaluation of the last symbolic result and store it in the Operation
            self.store_evaluation_result()

        self.trace_records.register(self.engine.get_ea(), operation, idx)
        logger.info(f"Registered operation with idx {idx}")
        next(self.operation_executed_count)

    def initialize_symbolic_evaluator(self):
        # We fetching the value of the registers before triggering the run
        # and store them in the global scope
        for reg_name in self.arch.REGISTERS:
            try:
                value = self.engine.read_reg(reg_name.upper())
                globals()[reg_name] = value
            except KeyError:
                pass
    
    def store_evaluation_result(self):
        """
        Now that qiling executed the last instruction, we fetch the result of the last operation given by the
        OperationEngine and compare it with qiling result
        """
        global logger
        last_trace_entry = self.trace_records.get_last_entry()
        if not last_trace_entry:
            return

        last_operation = last_trace_entry.operation
        cinsn_operands = last_operation.cinsn.operands
        last_v_result = last_operation.v_result

        if last_v_result is not None and len(cinsn_operands) > 0:
            op1 = cinsn_operands[0]

            if op1.type == X86_OP_REG:
                reg_name = get_reg_name(self.cs, op1.reg)
                value = self.engine.read_reg(reg_name)
                print(f"Read {reg_name} {value}")

            elif op1.type == X86_OP_MEM:
                value = self.engine.read_memory_int(last_operation.mem_access)

            if value:
                last_operation.op_result = value
                last_operation.eval_v_result = eval(str(last_v_result), globals())
                #print(self.symbolic_taint_store)
                logger.info(f"OP idx {self.operation_executed_count.value}, op_result {hex(last_operation.op_result)}, eval_v_result {hex(last_operation.eval_v_result)}")

    
    def evaluate_current_symbolic_state(self, operation: Operation):
        """
        Evaluate the current symbolic state of the registers and memory
        """
        # register new variables var_xxxxx
        vars_to_register = sorted(set(self.symbolic_taint_store.keys()).difference(set(globals().keys())))
        for var_name in vars_to_register:
            if var_name.startswith("VAR_"):
                globals()[var_name] = eval(str(self.symbolic_taint_store[var_name]), globals())

        # eval last mem access
        if operation.mem_access:
            name = create_name_from_address(operation.mem_access)
            if name in self.symbolic_taint_store:
                globals()[name] = eval(str(self.symbolic_taint_store[name]), globals())
            else:
                globals()[name] = self.engine.read_memory_int(operation.mem_access)

        # update registers values
        for op in operation.cinsn.operands:
            if op.type in [X86_OP_REG, ARM_OP_REG]:
                reg_name = get_reg_name(self.cs, op.reg)
                if reg_name in self.symbolic_taint_store:
                    globals()[reg_name] = eval(str(self.symbolic_taint_store[reg_name]), globals())

    def register_execution_state(self, current_operation: Operation, last_operation: Operation):
        idx = self.operation_executed_count.value

        for operation in (current_operation, last_operation):
            if operation is None:
                continue

            # Register last instructions changes
            for i in range(min(len(operation.cinsn.operands), 3)):
                operand = operation.cinsn.operands[i]

                if operand.type in [X86_OP_REG, ARM_OP_REG]:
                    # update the parent register
                    register_name = get_parent_register(get_reg_name(self.cs, operand.reg), self.CONFIG["BINARY_ARCH_SIZE"])
                    register_value = self.engine.read_reg(register_name.upper())
                    self.registers_state.register_item(register_name, idx, register_value)

                elif operand.type in [X86_OP_MEM, ARM_OP_MEM]:
                    address = operation.mem_access
                    if address is None:
                        continue
                    name = create_name_from_address(address)
                    memory_value = self.engine.read_memory_int(address)
                    self.memory_state.register_item(name, idx, memory_value)

        # register pc
        pc_name = self.CONFIG["PC_REG_NAME"]
        self.registers_state.register_item(pc_name, idx, self.engine.get_ea())
        # register sp
        sp_name = self.CONFIG["PC_REG_NAME"]
        self.registers_state.register_item(sp_name, idx, self.engine.get_stack_pointer())

    def initialize_execution_state(self):
        global logger
        for reg_name in self.arch.REGISTERS:
            try:
                register_value = self.engine.read_reg(reg_name.upper())
                self.registers_state.register_item(reg_name, 0, register_value)
                globals()[reg_name] = register_value
                logger.info(f"Registering {reg_name} with value {register_value}")
            except (KeyError, AttributeError) as e:
                logger.error("Failed to read {}".format(reg_name))
            
    def initialize_configuration(self):
        """
        Initialize the global shared among all the modules via superglobal library
        """
        if isinstance(self.arch, ArchAMD64) or isinstance(self.arch, ArchX86):
            self.CONFIG["BAD_OPERANDS"] = BAD_OPERANDS_X86_64

        if isinstance(self.arch, ArchAMD64) or isinstance(self.arch, ArchARM64):
            self.CONFIG["BINARY_MAX_MASK"] = 0xFFFFFFFFFFFFFFFF
            self.CONFIG["BINARY_ARCH_SIZE"] = 64

        elif isinstance(self.arch, ArchX86) or isinstance(self.arch, ArchARM):
            self.CONFIG["BINARY_MAX_MASK"] = 0xFFFFFFFF
            self.CONFIG["BINARY_ARCH_SIZE"] = 32
            
        
        self.CONFIG["PC_REG_NAME"] = self.arch.IP
        self.CONFIG["SP_REG_NAME"] = self.arch.SP
    
        # make first update
        setglobal("CONFIG", self.CONFIG)
        # Must be called after CONFIG BINARY_MAX_MASK and BINARY_ARCH_SIZE are set
        self.CONFIG["SYM_REGISTER_FACTORY"] = create_sym_register_factory()
        self.CONFIG["IS_INITIALIZED"] = True
        # make second update
        setglobal("CONFIG", self.CONFIG)
        
        self.operation_engine.set_config(self.CONFIG)
        
    
    def process_analysis(self):
        global profile
        try:
            self.initialize_configuration()
            self.initialize_execution_state()
            self.initialize_symbolic_evaluator()
            while self.engine.is_next():
                self.register_operations(self.operation_engine.evaluate_instruction(self.symbolic_taint_store))
                self.engine.step()
        except Exception as e:
            profile.print_stats()
            raise e
        profile.print_stats()
        return self.trace_records
            
    def clone(self):
        self.engine.clear()
        new_runner = self.__class__(self.engine, self.timeout)
        # Copy the state of VariableStates
        new_runner.state = self.symbolic_taint_store.clone()
        # Copy architecture-specific attributes
        new_runner.cs = self.cs
        new_runner.ks = self.ks
        new_runner.operation_engine = self.operation_engine
        # Copy address book and trace records
        new_runner.trace_records = self.trace_records.clone()
        # Copy executed instructions count
        new_runner.operation_executed_count = self.operation_executed_count
        # copy data store
        new_runner.registers_state = self.registers_state.clone()
        new_runner.memory_state = self.memory_state.clone()
        return new_runner



