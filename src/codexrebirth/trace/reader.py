
import idaapi
import idc 

from ..integration.api import DisassemblerContextAPI
from .arch import ArchAMD64, ArchX86
from ..tools import *


class TraceReader(object):
    """
    A high level, debugger-like interface for querying Tenet traces.
    """

    def __init__(self, trace, registers_state, memory_state):
        self.idx = 0
        self.dctx = DisassemblerContextAPI()
        self._addr_trace_cache = trace

        # select a trace arch based on the binary the disassmbler has loaded
        if self.dctx.is_64bit():
            self.arch = ArchAMD64()
        else:
            self.arch = ArchX86()

        self._idx_cached_registers = -1
        self._cached_registers = {}
        self._idx_trace_cache = {}
        
        self.construct_trace_cache()
        self._taint_id_color_map = {}
        
        self._idx_changed_callbacks = []
        
        self.registers_state = registers_state
        self.memory_state = memory_state
        

    def construct_trace_cache(self):
        self._idx_trace_cache = {
            idx: (operation_addr, trace) 
            for operation_addr in self._addr_trace_cache 
            for idx, trace in self._addr_trace_cache[operation_addr].items()
        }

            
    #-------------------------------------------------------------------------
    # Trace Properties
    #-------------------------------------------------------------------------

    @property
    def rebased_ip(self):
        """
        Return the current instruction pointer, rebased to the loaded binary.
        """
        return self._idx_trace_cache[self.idx][0]
    
    @property
    def length(self):
        """
        Return the length of the trace.
        """
        return len(self._idx_trace_cache)
    
    @property
    def registers(self):
        """
        Return the current registers.
        """
        return self.get_registers()

    
    @property
    def current_taint_id(self):
        return self.get_trace(self.idx).taint_id
    

    #-------------------------------------------------------------------------
    # Trace Navigation
    #-------------------------------------------------------------------------
        
    def set_taint_id_color(self, taint_id, color):
        if taint_id not in self._taint_id_color_map:
            self._taint_id_color_map[taint_id] = color
        
    def get_taint_id_color(self, taint_id):
        if taint_id in self._taint_id_color_map:
            return self._taint_id_color_map[taint_id]
        return None
    
    def get_idx_color(self, idx):
        if idx not in self._idx_trace_cache:
            return None
        taint_id = self.get_trace(idx).taint_id
        return self.get_taint_id_color(taint_id)
    
    def is_computation_correct(self, idx):
        if idx not in self._idx_trace_cache:
            return False
        return self.get_trace(idx).operation.op_result == self.get_trace(idx).operation.eval_v_result
    
    def get_register(self, reg_name, idx=None):
        """
        Return a single register value.

        If a timestamp (idx) is provided, that will be used instead of the current timestamp.
        """
        return self.get_registers([reg_name], idx)[reg_name]
    
    def get_registers(self, reg_names=None, idx=None):
        """
        Return a dict of the requested registers and their values.

        If a list of registers (reg_names) is not provided, all registers will be returned.

        If a timestamp (idx) is provided, that will be used instead of the current timestamp.
        """
        if idx is None:
            idx = self.idx

        # no registers were specified, so we'll return *all* registers
        if reg_names is None:
            reg_names = get_regs_name()
            
        output_registers = {}
            
        for reg_name in reg_names:
            output_registers[reg_name] = self.registers_state.get_state(reg_name, idx)


        # return the register set for this trace index
        return output_registers
    
    
    def get_memory(self, address, length):
        """
        Return a memory region.
        """
        output = []
        idx = self.idx
        for addr in range(address, address + length, self.arch.POINTER_SIZE):
            name = create_name_from_address(addr)
            mem_state = self.memory_state.get_state(name, idx)
            if mem_state:
                output.append(mem_state)
            else:
                output.append(read_memory_int(addr, self.arch.POINTER_SIZE))
                
        # transform output to ByteArray
        bytes_data = bytearray()
        for interger in output:
            bytes_data += interger.to_bytes(self.arch.POINTER_SIZE, byteorder="little")
            
        
        return bytes_data

    
        

    def seek(self, idx):
        """
        Seek the trace to the given timestamp.
        """
        print("Seeking to idx: {}".format(idx))

        # clamp the index if it goes past the end of the trace
        if idx >= self.length:
            idx = self.length - 1
        elif idx < 0:
            idx = 0
        # save the new position
        self.idx = idx
        self.get_registers()
        addr = self.get_ip(idx)
        idaapi.jumpto(addr)
        self._notify_idx_changed()
        
        print("Current symbolic id: {}".format(self.current_taint_id))
        
    
    def get_current_function_bounds(self):
        """
        Return the bounds of the init function.
        """
        try:
            ea = self._idx_trace_cache[0][0]
            func = idaapi.get_func(ea) 
            return func.start_ea, func.end_ea
        except:
            return 0, 0
    
        
    def is_symbolic_instruction(self, idx):
        """
        Return True if the given address is symbolic.
        """
        if idx not in self._idx_trace_cache:
            return False
        if self.current_taint_id is None or self.current_taint_id == -1:
            return False
        return self.get_trace(idx).taint_id == self.current_taint_id
    
    
    def get_trace(self, idx):
        if idx not in self._idx_trace_cache:
            return None
        return self._idx_trace_cache[idx][1]
    

    def get_operation(self, idx):
        if idx not in self._idx_trace_cache:
            return None
        return self.get_trace(idx).operation
         
    def get_ip(self, idx):
        """
        Return the instruction pointer for the given timestamp.
        """
        if idx not in self._idx_trace_cache:
            return None
        return self._idx_trace_cache[idx][0]


    def seek_percent(self, percent):
        """
        Seek to an approximate percentage into the trace.
        """
        target_idx = int(self.length * (percent / 100))
        self.seek(target_idx)
        

    def seek_to_first(self, address):
        """
        Seek to the first instance of the given breakpoint.

        Returns True on success, False otherwise.
        """
        return self.seek_to_next(address)

    def seek_to_final(self, address):
        """
        Seek to the final instance of the given breakpoint.

        Returns True on success, False otherwise.
        """
        return self.seek_to_prev(address)

    def seek_to_next(self, address,start_idx=None):
        """
        Seek to the next instance of the given breakpoint.

        Returns True on success, False otherwise.
        """
       
        idx = self.find_next_execution(address, start_idx)
        self.seek(idx)
        return True
    
    def seek_to_current(self, address):
        """
        Seek to the given address.
        """
        idx = self.find_current_execution(address)
        self.seek(idx)
        return True

    def seek_to_prev(self, address, start_idx=None):
        """
        Seek to the previous instance of the given breakpoint.

        Returns True on success, False otherwise.
        """
   
        idx = self.find_prev_execution(address, start_idx)
        self.seek(idx)
        return True

    def step_forward(self, n=1, step_over=False):
        """
        Step the trace forward by n steps.

        If step_over=True, and a disassembler context is available to the
        trace reader, it will attempt to step over calls while stepping.
        """
        if not step_over:
            self.seek(self.idx + n)
        else:
            self._step_over_forward(n)

    def step_backward(self, n=1, step_over=False):
        """
        Step the trace backwards.

        If step_over=True, and a disassembler context is available to the
        trace reader, it will attempt to step over calls while stepping.
        """
        if not step_over:
            self.seek(self.idx - n)
        else:
            self._step_over_backward(n)

    def _step_over_forward(self, n):
        """
        Step the trace forward over n instructions / calls.
        """
        address = self.get_ip(self.idx)
        #
        # get the address for the linear instruction address after the
        # current instruction
        #

        next_address = self.dctx.get_next_operation(address)
        if next_address  == -1:
            self.seek(self.idx + 1)
            return

        next_idx = self.find_next_execution(next_address, self.idx)

        #
        # the instruction after the call does not appear in the trace,
        # so just fall-back to 'step into' behavior
        #
        if next_idx == -1:
            self.seek(self.idx + 1)
            return

        self.seek(next_idx)




    def get_executions(self, address, resolution=1):
        """
        Return a list of timestamps (idx) that executed the given address.
        """
        return self.get_executions_between(address, 0, self.length, resolution)

    def get_executions_between(self, start_idx, end_idx, resolution=1):
        """
        Return a list of timestamps (idx) that executed the given address, in the given slice.
        """
        executions = []
        for idx in range(start_idx, end_idx, resolution):
                executions.append(idx)
        return executions


    def get_prev_ips(self, n, step_over=False):
        """
        Return the previous n executed instruction addresses.

        If step_over=True, and a disassembler context is available to the
        trace reader, it will attempt to step over calls while stepping.
        """

        dctx, idx = self.dctx, self.idx
        return [self.get_ip(max(idx - i, 0)) for i in range(n)]

    def get_next_ips(self, n, step_over=False):
        """
        Return the next N executed instruction addresses.

        If step_over=True, and a disassembler context is available to the
        trace reader, it will attempt to step over calls while stepping.
        """

        dctx, idx = self.dctx, self.idx
        return [self.get_ip(min(idx + i, self.length - 1)) for i in range(n)]


    def find_next_execution(self, address, idx=None):
        """
        Return the next timestamp to execute the given address.
        """
        addr_timestamps = self._addr_trace_cache[address].keys()
        # sort the timestamps
        addr_timestamps = sorted(addr_timestamps)
        # find the index of the current timestamp
        if idx is None:
            idx = self.idx
        try:
            idx_index = addr_timestamps.index(idx)
        except ValueError:
            idx_index = 0
        # return the next timestamp
        if idx_index < len(addr_timestamps) - 1:
            return addr_timestamps[idx_index + 1]
        # fail, reached start of trace
        return self.idx
    
    
    def find_current_execution(self, address, idx=None):
        addr_timestamps = self._addr_trace_cache[address].keys()
        print("addr_timestamps: {}".format(addr_timestamps))
        # sort the timestamps
        addr_timestamps = sorted(addr_timestamps)
        # find the index of the current timestamp
        if idx is None:
            idx = self.idx
        try:
            idx_index = addr_timestamps.index(idx)
        except ValueError:
            idx_index = 0
        # return the next timestamp
        if idx_index < len(addr_timestamps) - 1:
            return addr_timestamps[idx_index]
        # fail, reached start of trace
        return self.idx

    def find_prev_execution(self, address, idx=None):
        """
        Return the previous timestamp to execute the given address.
        """
        addr_timestamps = self._addr_trace_cache[address].keys()
        # sort the timestamps 
        addr_timestamps = sorted(addr_timestamps)
        # find the index of the current timestamp
        if idx is None:
            idx = self.idx
            
        try:
            idx_index = addr_timestamps.index(idx)
        except ValueError:
            idx_index = 0
        # return the previous timestamp
        if idx > 0:
            return addr_timestamps[idx_index - 1]
        
        return self.idx
            
            
    def idx_changed(self, callback):
        """
        Subscribe a callback for a trace navigation event.
        """
        register_callback(self._idx_changed_callbacks, callback)
        

    def _notify_idx_changed(self):
        """
        Notify listeners of an idx changed event.
        """
        notify_callback(self._idx_changed_callbacks, self.idx)

