value = "000000001111111122222222333333334444444455555555666666666"

# num \+ (0x[0-9A-F]*) -> long(value[$1:$1+8])

BINARY_ARCH_SIZE = 64
BINARY_MAX_MASK = 0xffffffffffffffff
# Must only be used with 'eval' function to evaluate the expression
def RotateLeft(x, n):
    return ((x << n) | (x >> (BINARY_ARCH_SIZE - n))) & BINARY_MAX_MASK


# Must only be used with 'eval' function to evaluate the expression
def RotateRight(x, n):
    return ((x >> n) | (x << (BINARY_ARCH_SIZE - n))) & BINARY_MAX_MASK

def  long(value):
    return int(value, 16) 

num0 = long(value[0:0+8])
num8 = long(value[8:8+8])
num16 = long(value[16:16+8])
num24 = long(value[24:24+8])
num32 = long(value[32:32+8])
num40 = long(value[40:40+8])



    
var_00001 = (num32 + 0x30 & 0xffffffffffffffff) * 0xc3a5c85c97cb3127 & 0xffffffffffffffff
var_00002 = num24 + (var_00001 + num0 & 0xffffffffffffffff) & 0xffffffffffffffff
var_00003 = RotateRight(var_00001 + num0 & 0xffffffffffffffff,0x25)
var_00004 = (var_00001 + num0 & 0xffffffffffffffff) + num8 & 0xffffffffffffffff
var_00005 = num24 + (var_00004 + num16 & 0xffffffffffffffff) & 0xffffffffffffffff
var_00006 = RotateRight(var_00004 + num16 & 0xffffffffffffffff,0x1f)
var_00007 = (var_00003 + RotateRight(var_00004,0x7) & 0xffffffffffffffff) + (RotateRight(var_00002,0x34) + var_00006 & 0xffffffffffffffff) & 0xffffffffffffffff
var_00008 = num40 + (num16 + num16 & 0xffffffffffffffff) & 0xffffffffffffffff
var_00009 = RotateRight(num16 + num16 & 0xffffffffffffffff,0x25)
var_00010 = (num16 + num16 & 0xffffffffffffffff) + num24 & 0xffffffffffffffff
var_00011 = num40 + (var_00010 + num32 & 0xffffffffffffffff) & 0xffffffffffffffff
var_00012 = RotateRight(var_00010 + num32 & 0xffffffffffffffff,0x1f)
var_00013 = (var_00009 + RotateRight(var_00010,0x7) & 0xffffffffffffffff) + (RotateRight(var_00008,0x34) + var_00012 & 0xffffffffffffffff) & 0xffffffffffffffff
var_00014 = (var_00005 + var_00013 & 0xffffffffffffffff) * 0x9ae16a3b2f90404f & 0xffffffffffffffff
var_00015 = (var_00011 + var_00007 & 0xffffffffffffffff) * 0xc3a5c85c97cb3127 & 0xffffffffffffffff
var_00016 = (var_00015 + var_00014 & 0xffffffffffffffff)>>0x2f & 0xffffffffffffffff ^ var_00015 + var_00014 & 0xffffffffffffffff
var_00017 = var_00007 + (var_00016 * 0xc3a5c85c97cb3127 & 0xffffffffffffffff) & 0xffffffffffffffff
var_00018 = (var_00017>>0x2f & 0xffffffffffffffff ^ var_00017) * 0x9ae16a3b2f90404f & 0xffffffffffffffff
rdi = var_00017
edi = var_00017
di = var_00017
dil = var_00017
rcx = var_00011 + var_00007 & 0xffffffffffffffff
ecx = var_00011 + var_00007 & 0xffffffffffffffff
cx = var_00011 + var_00007 & 0xffffffffffffffff
ch = var_00011 + var_00007 & 0xffffffffffffffff
cl = var_00011 + var_00007 & 0xffffffffffffffff
rax = var_00018
eax = var_00018
ax = var_00018
ah = var_00018
al = var_00018

mem_0x80000000dd78 = var_00016

"""
0x55555555527d   pop rbp
21:15:48  rbp => 0x80000000ddc8
0x55555555527e   ret 
0x5555555558ca   movabs rdx, 0x9ae16a3b2f90404f
21:15:48  Symbolic register found in rdx => var_00016 * 0xc3a5c85c97cb3127 & 0xffffffffffffffff
21:15:48  Symbolic operation gives no result
21:15:48  rdx = 0xf41b05441727507b 
21:15:48  rdx => 0x9ae16a3b2f90404f
0x5555555558d4   imul rax, rdx
21:15:48  Symbolic register found in rax => var_00017>>0x2f & 0xffffffffffffffff ^ var_00017
21:15:48  Symbolic instruction imul executed, result: (var_00017>>0x2f & 0xffffffffffffffff ^ var_00017) * 0x9ae16a3b2f90404f & 0xffffffffffffffff
##############################################################################################
21:15:48  rax => 0xe7d41dd77717d7af   <------------ HERE IS THE RESULT !!!!!!!!!!!!!!!
##############################################################################################
21:15:48  rdx => 0x9ae16a3b2f90404f
0x5555555558d8   mov rbx, qword ptr [rbp - 8]
21:15:48  Symbolic register found in rbx => num16
21:15:48  Creating new varname var_00018 for rax=>(var_00017>>0x2f & 0xffffffffffffffff ^ var_00017) * 0x9ae16a3b2f90404f & 0xffffffffffffffff
21:15:48  Instantiating v_op2 RealValue
21:15:48  Symbolic operation gives no result
21:15:48  rbx = 0x22222222 
21:15:48  0x80000000ddc0 = 0x0
21:15:48  rbx => 0x0
21:15:48  0x80000000ddc0 => 0x0
0x5555555558dc   leave 
0x5555555558dd   ret 
0x555555555949   jmp 0x555555555c50
0x555555555c50   add rsp, 0x50
21:15:48  rsp => 0x80000000de28
0x555555555c54   pop rbx
21:15:48  rbx => 0x0
0x555555555c55   pop r12
21:15:48  r12 => 0x0
0x555555555c57   pop rbp
21:15:48  rbp => 0x80000000de58
0x555555555c58   ret 
0x55555555666f   leave 
0x555555556670   ret 
"""


assert rax == 0xe7d41dd77717d7af