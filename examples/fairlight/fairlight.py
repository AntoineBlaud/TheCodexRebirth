
from qiling import *
from qiling.const import QL_VERBOSE
from superglobals import setglobal
from sys import argv

# Set global variable 'BINARY_ARCH' to 2
setglobal('BINARY_ARCH', "x64")

from codexrebirth import CodexRebirth, DebugLevel

##############################################################################################
# IMPORTANT: address depend of you system, you need to change the address and disable aslr 
# or use qiling base + offset
##############################################################################################


"""
.text:0000000000401905 
.text:0000000000401905 public main
.text:0000000000401905 main proc near                          
.text:0000000000401905
.text:0000000000401905 var_1C0= qword ptr -1C0h
.text:0000000000401905 var_1B4= dword ptr -1B4h
.text:0000000000401905 s= byte ptr -1B0h
.text:0000000000401905 var_1A8= byte ptr -1A8h
.text:0000000000401905 var_18= qword ptr -18h
.text:0000000000401905
.text:0000000000401905 
.text:0000000000401905 push    rbp
.text:0000000000401906 mov     rbp, rsp
.text:0000000000401909 push    rbx
.text:000000000040190A sub     rsp, 1B8h
.text:0000000000401911 mov     [rbp+var_1B4], edi
.text:0000000000401917 mov     [rbp+var_1C0], rsi
.text:000000000040191E mov     rax, fs:28h
.text:0000000000401927 mov     [rbp+var_18], rax
.text:000000000040192B xor     eax, eax
.text:000000000040192D mov     qword ptr [rbp+s], 0
.text:0000000000401938 lea     rsi, [rbp+var_1A8]
.text:000000000040193F mov     eax, 0
.text:0000000000401944 mov     edx, 31h 
.text:0000000000401949 mov     rdi, rsi
.text:000000000040194C mov     rcx, rdx
.text:000000000040194F rep stosq
.text:0000000000401952 cmp     [rbp+var_1B4], 1
.text:0000000000401959 jg      short loc_40196F
.text:000000000040195B mov     edi, offset s                   
.text:0000000000401960 call    _puts
.text:0000000000401965 mov     edi, 0                          
.text:000000000040196A call    _exit
.text:000000000040196F
.text:000000000040196F loc_40196F:                             
.text:000000000040196F mov     rax, [rbp+var_1C0]
.text:0000000000401976 add     rax, 8
.text:000000000040197A mov     rax, [rax]
.text:000000000040197D mov     rdi, rax                        
.text:0000000000401980 call    _strlen
.text:0000000000401985 cmp     rax, 0Eh
.text:0000000000401989 jz      short loc_401995
.text:000000000040198B mov     eax, 0
.text:0000000000401990 call    denied_access
.text:0000000000401995
.text:0000000000401995 loc_401995:                             
.text:0000000000401995 mov     rax, [rbp+var_1C0]
.text:000000000040199C add     rax, 8
.text:00000000004019A0 mov     rax, [rax]
.text:00000000004019A3 mov     edx, 28h SECRET
.text:00000000004019A8 mov     rsi, rax                        
.text:00000000004019AB mov     edi, offset code     ; offset code = 0x6030B8            
.text:00000000004019B0 call    _strncpy
.text:00000000004019B5 mov     eax, 0               ; EMU START HERE
.text:00000000004019BA call    check_0
.text:00000000004019BF mov     eax, 0
.text:00000000004019C4 call    check_1
.text:00000000004019C9 mov     eax, 0
.text:00000000004019CE call    check_2
.text:00000000004019D3 mov     eax, 0
.text:00000000004019D8 call    check_3
.text:00000000004019DD mov     eax, 0
.text:00000000004019E2 call    check_4
.text:00000000004019E7 mov     eax, 0
.text:00000000004019EC call    check_5
.text:00000000004019F1 mov     eax, 0
.text:00000000004019F6 call    check_6
.text:00000000004019FB mov     eax, 0
.text:0000000000401A00 call    check_7
.text:0000000000401A05 mov     eax, 0
.text:0000000000401A0A call    check_8
.text:0000000000401A0F mov     eax, 0
.text:0000000000401A14 call    check_9
.text:0000000000401A19 mov     eax, 0
.text:0000000000401A1E call    check_10
.text:0000000000401A23 mov     eax, 0
.text:0000000000401A28 call    check_11
.text:0000000000401A2D mov     eax, 0
.text:0000000000401A32 call    check_12
.text:0000000000401A37 mov     eax, 0
.text:0000000000401A3C call    check_13



text:000000000040076F check_0 proc near                       
.text:000000000040076F
.text:000000000040076F var_8= dword ptr -8
.text:000000000040076F var_4= dword ptr -4
.text:000000000040076F
.text:000000000040076F 
.text:000000000040076F push    rbp
.text:0000000000400770 mov     rbp, rsp
.text:0000000000400773 sub     rsp, 10h
.text:0000000000400777 call    _rand                ; Rand hook
.text:000000000040077C cvtsi2ss xmm0, eax
.text:0000000000400780 movss   xmm1, cs:dword_401B40
.text:0000000000400788 divss   xmm0, xmm1
.text:000000000040078C movss   [rbp+var_8], xmm0
.text:0000000000400791 call    _rand                ; Rand hook
.text:0000000000400796 cvtsi2ss xmm0, eax
.text:000000000040079A movss   xmm1, cs:dword_401B40
"""




# Define a function to register 'secret_valueBB' in memory
def register(codex, code_value):
    offset_code = 0x6030B8
    value = code_value
    codex.ql.mem.write(offset_code, value.encode())
    value = codex.ql.mem.read(offset_code, 1)
    index = 0
    while value != b'\x00':
        # For each byte of the string, taint the memory and apply a mask of 0xff
        # Example: call 1 -> (0x6030B8, in_0, code_value[0], 0xff)
        codex.taint_memory(offset_code + index, "in_"+str(index), int.from_bytes(value, byteorder='little'), 0xff)
        index += 1
        value = codex.ql.mem.read(offset_code + index, 1)



# Configure Qiling with verbose logging
ql = Qiling([*argv[1:]], r"/opt/qiling/examples/rootfs/x8664_linux")
debug_level = DebugLevel.DEBUG

# Initialize the CodexRebirth instance
codex = CodexRebirth(ql, debug_level, strict_symbolic_check=False)

# Define a callback for the 'rand' function
def rand_callback(codex):
    ql = codex.ql
    print("rand_callback")
    ql.arch.regs.write("rax", 0x1)
    # Move to the next instruction
    ql.arch.regs.write("rip", ql.arch.regs.read("rip") + 0x5)
    

# Register 'rand_callback' for specific addresses for check 1
codex.register_callback(0x400777, rand_callback)
codex.register_callback(0x400791, rand_callback)

# Set the starting address for emulation
codex.set_emu_start(0x4019B5)


# Register 'secret_valueBB' in memory
register(codex, "secret_valueBB")

#Register 'rand_callback' for specific addresses for check 1
# codex.register_callback(0x4008B5, rand_callback)
# codex.register_callback(0x4008CF, rand_callback)




# Run the emulation
codex.run_emulation()

# Print the CodexRebirth state
print(codex.codex_state)
