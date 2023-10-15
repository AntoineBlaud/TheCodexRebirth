
from ida_codexrebirth.integration.api import disassembler, DisassemblerContextAPI
from ida_codexrebirth.trace.arch import ArchAMD64, ArchX86
import idaapi
import ida_codexrebirth.util.misc as utils

class TraceReader(object):
    """
    A high level, debugger-like interface for querying Tenet traces.
    """

    def __init__(self, trace):
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
        self._highlighted_address = None
        
        
    
        
    def construct_trace_cache(self):
        
 
        for insn_addr in self._addr_trace_cache:
            for idx in self._addr_trace_cache[insn_addr].keys():
                self._idx_trace_cache[idx] = (insn_addr, self._addr_trace_cache[insn_addr][idx])
                
        print("Trace cache constructed")
        
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
    def highlighted_address(self):
        """
        Return the currently highlighted address.
        """
        return self._highlighted_address



    #-------------------------------------------------------------------------
    # Trace Navigation
    #-------------------------------------------------------------------------
    def set_highlighted_address(self, address):
        if address in self._addr_trace_cache:
            self._highlighted_address = address
            return True


    def seek(self, idx):
        """
        Seek the trace to the given timestamp.
        """

        # clamp the index if it goes past the end of the trace
        if idx >= self.length:
            idx = self.length - 1
        elif idx < 0:
            idx = 0

        # save the new position
        self.idx = idx
        
        # set the ida instruction pointer
        self.dctx.set_ip(self.get_ip(idx))
        
    
        
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
    
        
    def is_symbolic(self, idx):
        """
        Return True if the given address is symbolic.
        """
        if idx not in self._idx_trace_cache:
            return False
        return self._idx_trace_cache[idx][1].is_symbolic
    
    
  
    
    def get_Insn(self, idx):
        if idx not in self._idx_trace_cache:
            return None
        return self._idx_trace_cache[idx][1].Insn
        
        
        
        
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

        next_address = self.dctx.get_next_insn(address)
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
            
            
