Output 1 







```
1:45:17  rbp => 0x80000000ddf8
11:45:17  rsp => 0x80000000ddf8
0x555555555928   sub rsp, 0x30
11:45:17  rsp => 0x80000000ddc8
0x55555555592c   mov qword ptr [rbp - 0x28], rdi
11:45:17  Symbolic memory found in register rdi => in_0
11:45:17  Instantiating v_op1 RealValue
11:45:17  Symbolic instruction mov executed, result: in_0
11:45:17  0x80000000ddd0 => 0x80000000dd78
11:45:17  rdi => 0x80000000dd78
0x555555555930   mov qword ptr [rbp - 0x30], rsi
11:45:17  Symbolic register found in rsi => num
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000ddd0 => 0x4141414141414141
Symbolic Computed Value : 65
11:45:17  Instantiating v_op1 RealValue
11:45:17  Symbolic instruction mov executed, result: num
11:45:17  0x80000000ddc8 => 0x22b8
11:45:17  rsi => 0x22b8
0x555555555934   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000ddd0 => 0x80000000dd78
0x555555555938   mov rdi, rax
11:45:17  Symbolic memory found in register rdi => in_0
11:45:17  Symbolic instruction mov executed, result: in_0
11:45:17  rdi => 0x80000000dd78
11:45:17  rax => 0x80000000dd78
0x55555555593b   call 0x555555555740
0x555555555740   push rbp
11:45:17  rbp => 0x80000000ddf8
0x555555555741   mov rbp, rsp
11:45:17  rbp => 0x80000000ddb8
11:45:17  rsp => 0x80000000ddb8
0x555555555744   sub rsp, 0x90
11:45:17  rsp => 0x80000000dd28
0x55555555574b   mov qword ptr [rbp - 0x88], rdi
11:45:17  Symbolic register found in rdi => in_0
11:45:17  Found a wrong symbolic memory value, deleting it: rdi => 0x4141414141414141
Symbolic Computed Value : 65
11:45:17  Instantiating v_op1 RealValue
11:45:17  Symbolic instruction mov executed, result: in_0
11:45:17  0x80000000dd30 => 0x80000000dd78
11:45:17  rdi => 0x80000000dd78
0x555555555752   movabs rax, 0x123456789abcdef
11:45:17  Symbolic memory found in register rax => in_0
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd30 => 0x4141414141414141
Symbolic Computed Value : 65
11:45:17  Symbolic operation gives no result
11:45:17  rax = 0x80000000dd78 0x4141414141414141
11:45:17  rax => 0x123456789abcdef
0x55555555575c   mov qword ptr [rbp - 0x20], rax
11:45:17  0x80000000dd98 => 0x123456789abcdef
11:45:17  rax => 0x123456789abcdef
0x555555555760   movabs rax, 0xfedcba9876543210
11:45:17  rax => 0xfedcba9876543210
0x55555555576a   mov qword ptr [rbp - 0x28], rax
11:45:17  0x80000000dd90 => 0xfedcba9876543210
11:45:17  rax => 0xfedcba9876543210
0x55555555576e   movabs rax, 0x2468ace13579bdf
11:45:17  rax => 0x2468ace13579bdf
0x555555555778   mov qword ptr [rbp - 0x30], rax
11:45:17  Symbolic memory found in 0x80000000dd88 => in_16
11:45:17  Loading a value from a previous symbolic memory write in_16
11:45:17  Symbolic operation gives no result
11:45:17  0x80000000dd88 = 0x41414141
11:45:17  rax = 0x2468ace13579bdf 
11:45:17  0x80000000dd88 => 0x2468ace13579bdf
11:45:17  rax => 0x2468ace13579bdf
0x55555555577c   movabs rax, 0xbdf13579ace02468
11:45:17  rax => 0xbdf13579ace02468
0x555555555786   mov qword ptr [rbp - 0x38], rax
11:45:17  Symbolic memory found in 0x80000000dd80 => in_8
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd89 => 0x9b
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd8a => 0x57
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd8b => 0x13
Symbolic Computed Value : 65
11:45:17  Loading a value from a previous symbolic memory write in_8
11:45:17  Symbolic operation gives no result
11:45:17  0x80000000dd80 = 0x4141414141414141
11:45:17  rax = 0xbdf13579ace02468 
11:45:17  0x80000000dd80 => 0xbdf13579ace02468
11:45:17  rax => 0xbdf13579ace02468
0x55555555578a   movabs rax, 0x13579bdf02468ace
11:45:17  rax => 0x13579bdf02468ace
0x555555555794   mov qword ptr [rbp - 0x40], rax
11:45:17  Symbolic memory found in 0x80000000dd78 => in_0
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd81 => 0x24
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd82 => 0xe0
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd83 => 0xac
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd84 => 0x79
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd85 => 0x35
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd86 => 0xf1
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd87 => 0xbd
Symbolic Computed Value : 65
11:45:17  Loading a value from a previous symbolic memory write in_0
11:45:17  Symbolic operation gives no result
11:45:17  0x80000000dd78 = 0x4141414141414141
11:45:17  rax = 0x13579bdf02468ace 
11:45:17  0x80000000dd78 => 0x13579bdf02468ace
11:45:17  rax => 0x13579bdf02468ace
0x555555555798   movabs rax, 0x9bdf02468ace1357
11:45:17  rax => 0x9bdf02468ace1357
0x5555555557a2   mov qword ptr [rbp - 0x48], rax
11:45:17  0x80000000dd70 => 0x9bdf02468ace1357
11:45:17  rax => 0x9bdf02468ace1357
0x5555555557a6   movabs rax, 0x2468ace13579bdf0
11:45:17  rax => 0x2468ace13579bdf0
0x5555555557b0   mov qword ptr [rbp - 0x50], rax
11:45:17  0x80000000dd68 => 0x2468ace13579bdf0
11:45:17  rax => 0x2468ace13579bdf0
0x5555555557b4   movabs rax, 0x3579bdf02468ace1
11:45:17  rax => 0x3579bdf02468ace1
0x5555555557be   mov qword ptr [rbp - 0x58], rax
11:45:17  0x80000000dd60 => 0x3579bdf02468ace1
11:45:17  rax => 0x3579bdf02468ace1
0x5555555557c2   movabs rax, 0xe13579bdf02468ac
11:45:17  rax => 0xe13579bdf02468ac
0x5555555557cc   mov qword ptr [rbp - 0x60], rax
11:45:17  0x80000000dd58 => 0xe13579bdf02468ac
11:45:17  rax => 0xe13579bdf02468ac
0x5555555557d0   movabs rax, 0x68ace13579bdf024
11:45:17  rax => 0x68ace13579bdf024
0x5555555557da   mov qword ptr [rbp - 0x68], rax
11:45:17  0x80000000dd50 => 0x68ace13579bdf024
11:45:17  rax => 0x68ace13579bdf024
0x5555555557de   movabs rax, 0x79bdf02468ace135
11:45:17  rax => 0x79bdf02468ace135
0x5555555557e8   mov qword ptr [rbp - 0x70], rax
11:45:17  0x80000000dd48 => 0x79bdf02468ace135
11:45:17  rax => 0x79bdf02468ace135
0x5555555557ec   movabs rax, 0xace13579bdf02468
11:45:17  rax => 0xace13579bdf02468
0x5555555557f6   mov qword ptr [rbp - 0x78], rax
11:45:17  0x80000000dd40 => 0xace13579bdf02468
11:45:17  rax => 0xace13579bdf02468
0x5555555557fa   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555801   mov rdi, rax
11:45:17  rdi => 0x80000000dd78
11:45:17  rax => 0x14
0x555555555809   mov qword ptr [rbp - 0x18], rax
11:45:17  0x80000000dda0 => 0x14
11:45:17  rax => 0x14
0x55555555580d   mov qword ptr [rbp - 8], 0
11:45:17  0x80000000ddb0 => 0x0
0x555555555815   jmp 0x5555555558bf
0x5555555558bf   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x14
11:45:17  0x80000000dda0 => 0x14
0x5555555558c3   shr rax, 3
11:45:17  rax => 0x2
0x5555555558c7   cmp qword ptr [rbp - 8], rax
11:45:17  0x80000000ddb0 => 0x0
11:45:17  rax => 0x2
0x5555555558cb   jb 0x55555555581a
0x55555555581a   mov qword ptr [rbp - 0x80], 0
11:45:17  0x80000000dd38 => 0x0
0x555555555822   mov dword ptr [rbp - 0xc], 0
11:45:17  0x80000000ddac => 0x0
0x555555555829   jmp 0x555555555869
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x0
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0x0
11:45:17  0x80000000dd38 => 0x0
0x55555555582f   shl rax, 8
11:45:17  rax => 0x0
0x555555555833   mov rdx, rax
11:45:17  rdx => 0x0
11:45:17  rax => 0x0
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x0
11:45:17  0x80000000ddb0 => 0x0
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x0
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x0
11:45:17  0x80000000ddac => 0x0
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0x0
11:45:17  rax => 0x0
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd78
11:45:17  rcx => 0x0
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0xce
11:45:17  0x80000000dd78 => 0x13579bdf02468ace
0x555555555857   movsx rax, al
11:45:17  rax => 0xffffffffffffffce
11:45:17  al => 0xce
0x55555555585b   movzx eax, al
11:45:17  eax => 0xce
11:45:17  al => 0xce
0x55555555585e   or rax, rdx
11:45:17  rax => 0xce
11:45:17  rdx => 0x0
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0xce
11:45:17  rax => 0xce
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x1
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x1
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0xce
11:45:17  0x80000000dd38 => 0xce
0x55555555582f   shl rax, 8
11:45:17  rax => 0xce00
0x555555555833   mov rdx, rax
11:45:17  rdx => 0xce00
11:45:17  rax => 0xce00
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x0
11:45:17  0x80000000ddb0 => 0x0
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x0
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x1
11:45:17  0x80000000ddac => 0x1
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0x1
11:45:17  rax => 0x1
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd79
11:45:17  rcx => 0x1
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  Symbolic memory found in 0x80000000dd79 => in_1
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd79 => 0x8a
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd7a => 0x46
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd7b => 0x2
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd7c => 0xdf
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd7d => 0x9b
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd7e => 0x57
Symbolic Computed Value : 65
11:45:17  Found a wrong symbolic memory value, deleting it: mem_0x80000000dd7f => 0x13
Symbolic Computed Value : 65
11:45:17  Instantiating v_op2 RealValue
11:45:17  Symbolic operation gives no result
11:45:17  eax = 0xdd79 
11:45:17  0x80000000dd79 = 0x6813579bdf02468a
11:45:17  eax => 0x8a
11:45:17  0x80000000dd79 => 0x6813579bdf02468a
0x555555555857   movsx rax, al
11:45:17  rax => 0xffffffffffffff8a
11:45:17  al => 0x8a
0x55555555585b   movzx eax, al
11:45:17  eax => 0x8a
11:45:17  al => 0x8a
0x55555555585e   or rax, rdx
11:45:17  rax => 0xce8a
11:45:17  rdx => 0xce00
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0xce8a
11:45:17  rax => 0xce8a
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x2
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x2
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0xce8a
11:45:17  0x80000000dd38 => 0xce8a
0x55555555582f   shl rax, 8
11:45:17  rax => 0xce8a00
0x555555555833   mov rdx, rax
11:45:17  rdx => 0xce8a00
11:45:17  rax => 0xce8a00
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x0
11:45:17  0x80000000ddb0 => 0x0
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x0
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x2
11:45:17  0x80000000ddac => 0x2
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0x2
11:45:17  rax => 0x2
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd7a
11:45:17  rcx => 0x2
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0x46
11:45:17  0x80000000dd7a => 0x246813579bdf0246
0x555555555857   movsx rax, al
11:45:17  rax => 0x46
11:45:17  al => 0x46
0x55555555585b   movzx eax, al
11:45:17  eax => 0x46
11:45:17  al => 0x46
0x55555555585e   or rax, rdx
11:45:17  rax => 0xce8a46
11:45:17  rdx => 0xce8a00
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0xce8a46
11:45:17  rax => 0xce8a46
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x3
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x3
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0xce8a46
11:45:17  0x80000000dd38 => 0xce8a46
0x55555555582f   shl rax, 8
11:45:17  rax => 0xce8a4600
0x555555555833   mov rdx, rax
11:45:17  rdx => 0xce8a4600
11:45:17  rax => 0xce8a4600
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x0
11:45:17  0x80000000ddb0 => 0x0
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x0
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x3
11:45:17  0x80000000ddac => 0x3
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0x3
11:45:17  rax => 0x3
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd7b
11:45:17  rcx => 0x3
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0x2
11:45:17  0x80000000dd7b => 0xe0246813579bdf02
0x555555555857   movsx rax, al
11:45:17  rax => 0x2
11:45:17  al => 0x2
0x55555555585b   movzx eax, al
11:45:17  eax => 0x2
11:45:17  al => 0x2
0x55555555585e   or rax, rdx
11:45:17  rax => 0xce8a4602
11:45:17  rdx => 0xce8a4600
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0xce8a4602
11:45:17  rax => 0xce8a4602
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x4
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x4
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0xce8a4602
11:45:17  0x80000000dd38 => 0xce8a4602
0x55555555582f   shl rax, 8
11:45:17  rax => 0xce8a460200
0x555555555833   mov rdx, rax
11:45:17  rdx => 0xce8a460200
11:45:17  rax => 0xce8a460200
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x0
11:45:17  0x80000000ddb0 => 0x0
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x0
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x4
11:45:17  0x80000000ddac => 0x4
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0x4
11:45:17  rax => 0x4
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd7c
11:45:17  rcx => 0x4
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0xdf
11:45:17  0x80000000dd7c => 0xace0246813579bdf
0x555555555857   movsx rax, al
11:45:17  rax => 0xffffffffffffffdf
11:45:17  al => 0xdf
0x55555555585b   movzx eax, al
11:45:17  eax => 0xdf
11:45:17  al => 0xdf
0x55555555585e   or rax, rdx
11:45:17  rax => 0xce8a4602df
11:45:17  rdx => 0xce8a460200
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0xce8a4602df
11:45:17  rax => 0xce8a4602df
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x5
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x5
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0xce8a4602df
11:45:17  0x80000000dd38 => 0xce8a4602df
0x55555555582f   shl rax, 8
11:45:17  rax => 0xce8a4602df00
0x555555555833   mov rdx, rax
11:45:17  rdx => 0xce8a4602df00
11:45:17  rax => 0xce8a4602df00
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x0
11:45:17  0x80000000ddb0 => 0x0
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x0
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x5
11:45:17  0x80000000ddac => 0x5
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0x5
11:45:17  rax => 0x5
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd7d
11:45:17  rcx => 0x5
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0x9b
11:45:17  0x80000000dd7d => 0x79ace0246813579b
0x555555555857   movsx rax, al
11:45:17  rax => 0xffffffffffffff9b
11:45:17  al => 0x9b
0x55555555585b   movzx eax, al
11:45:17  eax => 0x9b
11:45:17  al => 0x9b
0x55555555585e   or rax, rdx
11:45:17  rax => 0xce8a4602df9b
11:45:17  rdx => 0xce8a4602df00
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0xce8a4602df9b
11:45:17  rax => 0xce8a4602df9b
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x6
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x6
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0xce8a4602df9b
11:45:17  0x80000000dd38 => 0xce8a4602df9b
0x55555555582f   shl rax, 8
11:45:17  rax => 0xce8a4602df9b00
0x555555555833   mov rdx, rax
11:45:17  rdx => 0xce8a4602df9b00
11:45:17  rax => 0xce8a4602df9b00
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x0
11:45:17  0x80000000ddb0 => 0x0
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x0
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x6
11:45:17  0x80000000ddac => 0x6
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0x6
11:45:17  rax => 0x6
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd7e
11:45:17  rcx => 0x6
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0x57
11:45:17  0x80000000dd7e => 0x3579ace024681357
0x555555555857   movsx rax, al
11:45:17  rax => 0x57
11:45:17  al => 0x57
0x55555555585b   movzx eax, al
11:45:17  eax => 0x57
11:45:17  al => 0x57
0x55555555585e   or rax, rdx
11:45:17  rax => 0xce8a4602df9b57
11:45:17  rdx => 0xce8a4602df9b00
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0xce8a4602df9b57
11:45:17  rax => 0xce8a4602df9b57
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x7
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x7
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0xce8a4602df9b57
11:45:17  0x80000000dd38 => 0xce8a4602df9b57
0x55555555582f   shl rax, 8
11:45:17  rax => 0xce8a4602df9b5700
0x555555555833   mov rdx, rax
11:45:17  rdx => 0xce8a4602df9b5700
11:45:17  rax => 0xce8a4602df9b5700
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x0
11:45:17  0x80000000ddb0 => 0x0
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x0
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x7
11:45:17  0x80000000ddac => 0x7
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0x7
11:45:17  rax => 0x7
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd7f
11:45:17  rcx => 0x7
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0x13
11:45:17  0x80000000dd7f => 0xf13579ace0246813
0x555555555857   movsx rax, al
11:45:17  rax => 0x13
11:45:17  al => 0x13
0x55555555585b   movzx eax, al
11:45:17  eax => 0x13
11:45:17  al => 0x13
0x55555555585e   or rax, rdx
11:45:17  rax => 0xce8a4602df9b5713
11:45:17  rdx => 0xce8a4602df9b5700
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0xce8a4602df9b5713
11:45:17  rax => 0xce8a4602df9b5713
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x8
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x8
0x55555555586d   jle 0x55555555582b
0x55555555586f   lea r9, [rbp - 0x40]
11:45:17  r9 => 0x80000000dd78
11:45:17  0x80000000dd78 => 0x13579bdf02468ace
0x555555555873   lea r8, [rbp - 0x38]
11:45:17  r8 => 0x80000000dd80
11:45:17  0x80000000dd80 => 0xbdf13579ace02468
0x555555555877   lea rcx, [rbp - 0x30]
11:45:17  rcx => 0x80000000dd88
11:45:17  0x80000000dd88 => 0x2468ace13579bdf
0x55555555587b   lea rdx, [rbp - 0x28]
11:45:17  rdx => 0x80000000dd90
11:45:17  0x80000000dd90 => 0xfedcba9876543210
0x55555555587f   lea rsi, [rbp - 0x20]
11:45:17  Symbolic register found in rsi => num
11:45:17  Instantiating v_op2 RealValue
11:45:17  Symbolic operation gives no result
11:45:17  rsi = 0x22b8 
11:45:17  0x80000000dd98 = 0x123456789abcdef
11:45:17  rsi => 0x80000000dd98
11:45:17  0x80000000dd98 => 0x123456789abcdef
0x555555555883   lea rax, [rbp - 0x80]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dd38 => 0xce8a4602df9b5713
0x555555555887   sub rsp, 8
11:45:17  rsp => 0x80000000dd20
0x55555555588b   lea rdi, [rbp - 0x78]
11:45:17  rdi => 0x80000000dd40
11:45:17  0x80000000dd40 => 0xace13579bdf02468
0x55555555588f   push rdi
11:45:17  rdi => 0x80000000dd40
0x555555555890   lea rdi, [rbp - 0x70]
11:45:17  rdi => 0x80000000dd48
11:45:17  0x80000000dd48 => 0x79bdf02468ace135
0x555555555894   push rdi
11:45:17  rdi => 0x80000000dd48
0x555555555895   lea rdi, [rbp - 0x68]
11:45:17  rdi => 0x80000000dd50
11:45:17  0x80000000dd50 => 0x68ace13579bdf024
0x555555555899   push rdi
11:45:17  rdi => 0x80000000dd50
0x55555555589a   lea rdi, [rbp - 0x60]
11:45:17  rdi => 0x80000000dd58
11:45:17  0x80000000dd58 => 0xe13579bdf02468ac
0x55555555589e   push rdi
11:45:17  rdi => 0x80000000dd58
0x55555555589f   lea rdi, [rbp - 0x58]
11:45:17  rdi => 0x80000000dd60
11:45:17  0x80000000dd60 => 0x3579bdf02468ace1
0x5555555558a3   push rdi
11:45:17  rdi => 0x80000000dd60
0x5555555558a4   lea rdi, [rbp - 0x50]
11:45:17  rdi => 0x80000000dd68
11:45:17  0x80000000dd68 => 0x2468ace13579bdf0
0x5555555558a8   push rdi
11:45:17  rdi => 0x80000000dd68
0x5555555558a9   lea rdi, [rbp - 0x48]
11:45:17  rdi => 0x80000000dd70
11:45:17  0x80000000dd70 => 0x9bdf02468ace1357
0x5555555558ad   push rdi
11:45:17  rdi => 0x80000000dd70
0x5555555558ae   mov rdi, rax
11:45:17  rdi => 0x80000000dd38
11:45:17  rax => 0x80000000dd38
0x5555555558b1   call 0x555555555179
0x555555555179   push rbp
11:45:17  rbp => 0x80000000ddb8
0x55555555517a   mov rbp, rsp
11:45:17  rbp => 0x80000000dcd8
11:45:17  rsp => 0x80000000dcd8
0x55555555517d   mov qword ptr [rbp - 8], rdi
11:45:17  0x80000000dcd0 => 0x80000000dd38
11:45:17  rdi => 0x80000000dd38
0x555555555181   mov qword ptr [rbp - 0x10], rsi
11:45:17  0x80000000dcc8 => 0x80000000dd98
11:45:17  rsi => 0x80000000dd98
0x555555555185   mov qword ptr [rbp - 0x18], rdx
11:45:17  0x80000000dcc0 => 0x80000000dd90
11:45:17  rdx => 0x80000000dd90
0x555555555189   mov qword ptr [rbp - 0x20], rcx
11:45:17  0x80000000dcb8 => 0x80000000dd88
11:45:17  rcx => 0x80000000dd88
0x55555555518d   mov qword ptr [rbp - 0x28], r8
11:45:17  0x80000000dcb0 => 0x80000000dd80
11:45:17  r8 => 0x80000000dd80
0x555555555191   mov qword ptr [rbp - 0x30], r9
11:45:17  0x80000000dca8 => 0x80000000dd78
11:45:17  r9 => 0x80000000dd78
0x555555555195   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x555555555199   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x123456789abcdef
11:45:17  0x80000000dd98 => 0x123456789abcdef
0x55555555519c   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x5555555551a0   mov rax, qword ptr [rax]
11:45:17  rax => 0xce8a4602df9b5713
11:45:17  0x80000000dd38 => 0xce8a4602df9b5713
0x5555555551a3   add rdx, rax
11:45:17  rdx => 0xcfad8b6a69472502
11:45:17  rax => 0xce8a4602df9b5713
0x5555555551a6   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x5555555551aa   mov qword ptr [rax], rdx
11:45:17  0x80000000dd98 => 0xcfad8b6a69472502
11:45:17  rdx => 0xcfad8b6a69472502
0x5555555551ad   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x5555555551b1   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x2468ace13579bdf
11:45:17  0x80000000dd88 => 0x2468ace13579bdf
0x5555555551b4   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x5555555551b8   mov rax, qword ptr [rax]
11:45:17  rax => 0x79bdf02468ace135
11:45:17  0x80000000dd48 => 0x79bdf02468ace135
0x5555555551bb   xor rdx, rax
11:45:17  rdx => 0x7bfb7aea7bfb7aea
11:45:17  rax => 0x79bdf02468ace135
0x5555555551be   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x5555555551c2   mov qword ptr [rax], rdx
11:45:17  0x80000000dd88 => 0x7bfb7aea7bfb7aea
11:45:17  rdx => 0x7bfb7aea7bfb7aea
0x5555555551c5   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555551c9   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xace13579bdf02468
11:45:17  0x80000000dd40 => 0xace13579bdf02468
0x5555555551cc   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x5555555551d0   mov rax, qword ptr [rax]
11:45:17  rax => 0xcfad8b6a69472502
11:45:17  0x80000000dd98 => 0xcfad8b6a69472502
0x5555555551d3   xor rdx, rax
11:45:17  rdx => 0x634cbe13d4b7016a
11:45:17  rax => 0xcfad8b6a69472502
0x5555555551d6   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555551da   mov qword ptr [rax], rdx
11:45:17  0x80000000dd40 => 0x634cbe13d4b7016a
11:45:17  rdx => 0x634cbe13d4b7016a
0x5555555551dd   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x5555555551e1   mov rax, qword ptr [rax]
11:45:17  rax => 0xcfad8b6a69472502
11:45:17  0x80000000dd98 => 0xcfad8b6a69472502
0x5555555551e4   rol rax, 0xb
11:45:17  rax => 0x6c5b534a3928167d
0x5555555551e8   mov rdx, rax
11:45:17  rdx => 0x6c5b534a3928167d
11:45:17  rax => 0x6c5b534a3928167d
0x5555555551eb   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x5555555551ef   mov qword ptr [rax], rdx
11:45:17  0x80000000dd98 => 0x6c5b534a3928167d
11:45:17  rdx => 0x6c5b534a3928167d
0x5555555551f2   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555551f6   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x634cbe13d4b7016a
11:45:17  0x80000000dd40 => 0x634cbe13d4b7016a
0x5555555551f9   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555551fd   mov rax, qword ptr [rax]
11:45:17  rax => 0xfedcba9876543210
11:45:17  0x80000000dd90 => 0xfedcba9876543210
0x555555555200   add rdx, rax
11:45:17  rdx => 0x622978ac4b0b337a
11:45:17  rax => 0xfedcba9876543210
0x555555555203   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x555555555207   mov qword ptr [rax], rdx
11:45:17  0x80000000dd40 => 0x622978ac4b0b337a
11:45:17  rdx => 0x622978ac4b0b337a
0x55555555520a   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x55555555520e   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xfedcba9876543210
11:45:17  0x80000000dd90 => 0xfedcba9876543210
0x555555555211   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x555555555215   add rax, 8
11:45:17  rax => 0x80000000dd40
0x555555555219   mov rax, qword ptr [rax]
11:45:17  rax => 0x622978ac4b0b337a
11:45:17  0x80000000dd40 => 0x622978ac4b0b337a
0x55555555521c   add rdx, rax
11:45:17  rdx => 0x61063344c15f658a
11:45:17  rax => 0x622978ac4b0b337a
0x55555555521f   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x555555555223   mov qword ptr [rax], rdx
11:45:17  0x80000000dd90 => 0x61063344c15f658a
11:45:17  rdx => 0x61063344c15f658a
0x555555555226   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x55555555522a   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xbdf13579ace02468
11:45:17  0x80000000dd80 => 0xbdf13579ace02468
0x55555555522d   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x555555555231   mov rax, qword ptr [rax]
11:45:17  rax => 0x622978ac4b0b337a
11:45:17  0x80000000dd40 => 0x622978ac4b0b337a
0x555555555234   xor rdx, rax
11:45:17  rdx => 0xdfd84dd5e7eb1712
11:45:17  rax => 0x622978ac4b0b337a
0x555555555237   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x55555555523b   mov qword ptr [rax], rdx
11:45:17  0x80000000dd80 => 0xdfd84dd5e7eb1712
11:45:17  rdx => 0xdfd84dd5e7eb1712
0x55555555523e   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x555555555242   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x6c5b534a3928167d
11:45:17  0x80000000dd98 => 0x6c5b534a3928167d
0x555555555245   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x555555555249   mov rax, qword ptr [rax]
11:45:17  rax => 0x61063344c15f658a
11:45:17  0x80000000dd90 => 0x61063344c15f658a
0x55555555524c   xor rdx, rax
11:45:17  rdx => 0xd5d600ef87773f7
11:45:17  rax => 0x61063344c15f658a
0x55555555524f   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x555555555253   mov qword ptr [rax], rdx
11:45:17  0x80000000dd98 => 0xd5d600ef87773f7
11:45:17  rdx => 0xd5d600ef87773f7
0x555555555256   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x55555555525a   mov rax, qword ptr [rax]
11:45:17  rax => 0x61063344c15f658a
11:45:17  0x80000000dd90 => 0x61063344c15f658a
0x55555555525d   rol rax, 0x20
11:45:17  rax => 0xc15f658a61063344
0x555555555261   mov rdx, rax
11:45:17  rdx => 0xc15f658a61063344
11:45:17  rax => 0xc15f658a61063344
0x555555555264   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x555555555268   mov qword ptr [rax], rdx
11:45:17  0x80000000dd90 => 0xc15f658a61063344
11:45:17  rdx => 0xc15f658a61063344
0x55555555526b   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x55555555526f   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xd5d600ef87773f7
11:45:17  0x80000000dd98 => 0xd5d600ef87773f7
0x555555555272   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x555555555276   mov rax, qword ptr [rax]
11:45:17  rax => 0x7bfb7aea7bfb7aea
11:45:17  0x80000000dd88 => 0x7bfb7aea7bfb7aea
0x555555555279   add rdx, rax
11:45:17  rdx => 0x8958daf97472eee1
11:45:17  rax => 0x7bfb7aea7bfb7aea
0x55555555527c   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x555555555280   mov qword ptr [rax], rdx
11:45:17  0x80000000dd98 => 0x8958daf97472eee1
11:45:17  rdx => 0x8958daf97472eee1
0x555555555283   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x555555555287   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x7bfb7aea7bfb7aea
11:45:17  0x80000000dd88 => 0x7bfb7aea7bfb7aea
0x55555555528a   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x55555555528e   add rax, 0x10
11:45:17  rax => 0x80000000dd48
0x555555555292   mov rax, qword ptr [rax]
11:45:17  rax => 0x79bdf02468ace135
11:45:17  0x80000000dd48 => 0x79bdf02468ace135
0x555555555295   add rdx, rax
11:45:17  rdx => 0xf5b96b0ee4a85c1f
11:45:17  rax => 0x79bdf02468ace135
0x555555555298   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x55555555529c   mov qword ptr [rax], rdx
11:45:17  0x80000000dd88 => 0xf5b96b0ee4a85c1f
11:45:17  rdx => 0xf5b96b0ee4a85c1f
0x55555555529f   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x5555555552a3   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x13579bdf02468ace
11:45:17  0x80000000dd78 => 0x13579bdf02468ace
0x5555555552a6   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x5555555552aa   mov rax, qword ptr [rax]
11:45:17  rax => 0x8958daf97472eee1
11:45:17  0x80000000dd98 => 0x8958daf97472eee1
0x5555555552ad   xor rdx, rax
11:45:17  rdx => 0x9a0f41267634642f
11:45:17  rax => 0x8958daf97472eee1
0x5555555552b0   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x5555555552b4   mov qword ptr [rax], rdx
11:45:17  0x80000000dd78 => 0x9a0f41267634642f
11:45:17  rdx => 0x9a0f41267634642f
0x5555555552b7   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555552bb   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xc15f658a61063344
11:45:17  0x80000000dd90 => 0xc15f658a61063344
0x5555555552be   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x5555555552c2   mov rax, qword ptr [rax]
11:45:17  rax => 0xf5b96b0ee4a85c1f
11:45:17  0x80000000dd88 => 0xf5b96b0ee4a85c1f
0x5555555552c5   xor rdx, rax
11:45:17  rdx => 0x34e60e8485ae6f5b
11:45:17  rax => 0xf5b96b0ee4a85c1f
0x5555555552c8   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555552cc   mov qword ptr [rax], rdx
11:45:17  0x80000000dd90 => 0x34e60e8485ae6f5b
11:45:17  rdx => 0x34e60e8485ae6f5b
0x5555555552cf   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x5555555552d3   mov rax, qword ptr [rax]
11:45:17  rax => 0xf5b96b0ee4a85c1f
11:45:17  0x80000000dd88 => 0xf5b96b0ee4a85c1f
0x5555555552d6   ror rax, 0x15
11:45:17  rax => 0x42e0ffadcb587725
0x5555555552da   mov rdx, rax
11:45:17  rdx => 0x42e0ffadcb587725
11:45:17  rax => 0x42e0ffadcb587725
0x5555555552dd   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x5555555552e1   mov qword ptr [rax], rdx
11:45:17  0x80000000dd88 => 0x42e0ffadcb587725
11:45:17  rdx => 0x42e0ffadcb587725
0x5555555552e4   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555552e8   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x34e60e8485ae6f5b
11:45:17  0x80000000dd90 => 0x34e60e8485ae6f5b
0x5555555552eb   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x5555555552ef   mov rax, qword ptr [rax]
11:45:17  rax => 0xdfd84dd5e7eb1712
11:45:17  0x80000000dd80 => 0xdfd84dd5e7eb1712
0x5555555552f2   add rdx, rax
11:45:17  rdx => 0x14be5c5a6d99866d
11:45:17  rax => 0xdfd84dd5e7eb1712
0x5555555552f5   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555552f9   mov qword ptr [rax], rdx
11:45:17  0x80000000dd90 => 0x14be5c5a6d99866d
11:45:17  rdx => 0x14be5c5a6d99866d
0x5555555552fc   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x555555555300   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xdfd84dd5e7eb1712
11:45:17  0x80000000dd80 => 0xdfd84dd5e7eb1712
0x555555555303   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x555555555307   add rax, 0x18
11:45:17  rax => 0x80000000dd50
0x55555555530b   mov rax, qword ptr [rax]
11:45:17  rax => 0x68ace13579bdf024
11:45:17  0x80000000dd50 => 0x68ace13579bdf024
0x55555555530e   add rdx, rax
11:45:17  rdx => 0x48852f0b61a90736
11:45:17  rax => 0x68ace13579bdf024
0x555555555311   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x555555555315   mov qword ptr [rax], rdx
11:45:17  0x80000000dd80 => 0x48852f0b61a90736
11:45:17  rdx => 0x48852f0b61a90736
0x555555555318   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x55555555531c   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x9bdf02468ace1357
11:45:17  0x80000000dd70 => 0x9bdf02468ace1357
0x55555555531f   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x555555555323   mov rax, qword ptr [rax]
11:45:17  rax => 0x14be5c5a6d99866d
11:45:17  0x80000000dd90 => 0x14be5c5a6d99866d
0x555555555326   xor rdx, rax
11:45:17  rdx => 0x8f615e1ce757953a
11:45:17  rax => 0x14be5c5a6d99866d
0x555555555329   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x55555555532d   mov qword ptr [rax], rdx
11:45:17  0x80000000dd70 => 0x8f615e1ce757953a
11:45:17  rdx => 0x8f615e1ce757953a
0x555555555330   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x555555555334   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x42e0ffadcb587725
11:45:17  0x80000000dd88 => 0x42e0ffadcb587725
0x555555555337   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x55555555533b   mov rax, qword ptr [rax]
11:45:17  rax => 0x48852f0b61a90736
11:45:17  0x80000000dd80 => 0x48852f0b61a90736
0x55555555533e   xor rdx, rax
11:45:17  rdx => 0xa65d0a6aaf17013
11:45:17  rax => 0x48852f0b61a90736
0x555555555341   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x555555555345   mov qword ptr [rax], rdx
11:45:17  0x80000000dd88 => 0xa65d0a6aaf17013
11:45:17  rdx => 0xa65d0a6aaf17013
0x555555555348   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x55555555534c   mov rax, qword ptr [rax]
11:45:17  rax => 0x48852f0b61a90736
11:45:17  0x80000000dd80 => 0x48852f0b61a90736
0x55555555534f   rol rax, 0x1f
11:45:17  rax => 0xb0d4839b24429785
0x555555555353   mov rdx, rax
11:45:17  rdx => 0xb0d4839b24429785
11:45:17  rax => 0xb0d4839b24429785
0x555555555356   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x55555555535a   mov qword ptr [rax], rdx
11:45:17  0x80000000dd80 => 0xb0d4839b24429785
11:45:17  rdx => 0xb0d4839b24429785
0x55555555535d   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x555555555361   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xa65d0a6aaf17013
11:45:17  0x80000000dd88 => 0xa65d0a6aaf17013
0x555555555364   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x555555555368   mov rax, qword ptr [rax]
11:45:17  rax => 0x9a0f41267634642f
11:45:17  0x80000000dd78 => 0x9a0f41267634642f
0x55555555536b   add rdx, rax
11:45:17  rdx => 0xa47511cd2125d442
11:45:17  rax => 0x9a0f41267634642f
0x55555555536e   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x555555555372   mov qword ptr [rax], rdx
11:45:17  0x80000000dd88 => 0xa47511cd2125d442
11:45:17  rdx => 0xa47511cd2125d442
0x555555555375   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x555555555379   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x9a0f41267634642f
11:45:17  0x80000000dd78 => 0x9a0f41267634642f
0x55555555537c   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x555555555380   add rax, 0x20
11:45:17  rax => 0x80000000dd58
0x555555555384   mov rax, qword ptr [rax]
11:45:17  rax => 0xe13579bdf02468ac
11:45:17  0x80000000dd58 => 0xe13579bdf02468ac
0x555555555387   add rdx, rax
11:45:17  rdx => 0x7b44bae46658ccdb
11:45:17  rax => 0xe13579bdf02468ac
0x55555555538a   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x55555555538e   mov qword ptr [rax], rdx
11:45:17  0x80000000dd78 => 0x7b44bae46658ccdb
11:45:17  rdx => 0x7b44bae46658ccdb
0x555555555391   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555395   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x2468ace13579bdf0
11:45:17  0x80000000dd68 => 0x2468ace13579bdf0
0x555555555398   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x55555555539c   mov rax, qword ptr [rax]
11:45:17  rax => 0xa47511cd2125d442
11:45:17  0x80000000dd88 => 0xa47511cd2125d442
0x55555555539f   xor rdx, rax
11:45:17  rdx => 0x801dbd2c145c69b2
11:45:17  rax => 0xa47511cd2125d442
0x5555555553a2   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x5555555553a6   mov qword ptr [rax], rdx
11:45:17  0x80000000dd68 => 0x801dbd2c145c69b2
11:45:17  rdx => 0x801dbd2c145c69b2
0x5555555553a9   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x5555555553ad   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xb0d4839b24429785
11:45:17  0x80000000dd80 => 0xb0d4839b24429785
0x5555555553b0   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x5555555553b4   mov rax, qword ptr [rax]
11:45:17  rax => 0x7b44bae46658ccdb
11:45:17  0x80000000dd78 => 0x7b44bae46658ccdb
0x5555555553b7   xor rdx, rax
11:45:17  rdx => 0xcb90397f421a5b5e
11:45:17  rax => 0x7b44bae46658ccdb
0x5555555553ba   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x5555555553be   mov qword ptr [rax], rdx
11:45:17  0x80000000dd80 => 0xcb90397f421a5b5e
11:45:17  rdx => 0xcb90397f421a5b5e
0x5555555553c1   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x5555555553c5   mov rax, qword ptr [rax]
11:45:17  rax => 0x7b44bae46658ccdb
11:45:17  0x80000000dd78 => 0x7b44bae46658ccdb
0x5555555553c8   rol rax, 0x11
11:45:17  rax => 0x75c8ccb199b6f689
0x5555555553cc   mov rdx, rax
11:45:17  rdx => 0x75c8ccb199b6f689
11:45:17  rax => 0x75c8ccb199b6f689
0x5555555553cf   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x5555555553d3   mov qword ptr [rax], rdx
11:45:17  0x80000000dd78 => 0x75c8ccb199b6f689
11:45:17  rdx => 0x75c8ccb199b6f689
0x5555555553d6   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x5555555553da   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xcb90397f421a5b5e
11:45:17  0x80000000dd80 => 0xcb90397f421a5b5e
0x5555555553dd   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x5555555553e1   mov rax, qword ptr [rax]
11:45:17  rax => 0x8f615e1ce757953a
11:45:17  0x80000000dd70 => 0x8f615e1ce757953a
0x5555555553e4   add rdx, rax
11:45:17  rdx => 0x5af1979c2971f098
11:45:17  rax => 0x8f615e1ce757953a
0x5555555553e7   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x5555555553eb   mov qword ptr [rax], rdx
11:45:17  0x80000000dd80 => 0x5af1979c2971f098
11:45:17  rdx => 0x5af1979c2971f098
0x5555555553ee   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x5555555553f2   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x8f615e1ce757953a
11:45:17  0x80000000dd70 => 0x8f615e1ce757953a
0x5555555553f5   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x5555555553f9   add rax, 0x28
11:45:17  rax => 0x80000000dd60
0x5555555553fd   mov rax, qword ptr [rax]
11:45:17  rax => 0x3579bdf02468ace1
11:45:17  0x80000000dd60 => 0x3579bdf02468ace1
0x555555555400   add rdx, rax
11:45:17  rdx => 0xc4db1c0d0bc0421b
11:45:17  rax => 0x3579bdf02468ace1
0x555555555403   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x555555555407   mov qword ptr [rax], rdx
11:45:17  0x80000000dd70 => 0xc4db1c0d0bc0421b
11:45:17  rdx => 0xc4db1c0d0bc0421b
0x55555555540a   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x55555555540e   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x3579bdf02468ace1
11:45:17  0x80000000dd60 => 0x3579bdf02468ace1
0x555555555411   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x555555555415   mov rax, qword ptr [rax]
11:45:17  rax => 0x5af1979c2971f098
11:45:17  0x80000000dd80 => 0x5af1979c2971f098
0x555555555418   xor rdx, rax
11:45:17  rdx => 0x6f882a6c0d195c79
11:45:17  rax => 0x5af1979c2971f098
0x55555555541b   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x55555555541f   mov qword ptr [rax], rdx
11:45:17  0x80000000dd60 => 0x6f882a6c0d195c79
11:45:17  rdx => 0x6f882a6c0d195c79
0x555555555422   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x555555555426   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x75c8ccb199b6f689
11:45:17  0x80000000dd78 => 0x75c8ccb199b6f689
0x555555555429   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x55555555542d   mov rax, qword ptr [rax]
11:45:17  rax => 0xc4db1c0d0bc0421b
11:45:17  0x80000000dd70 => 0xc4db1c0d0bc0421b
0x555555555430   xor rdx, rax
11:45:17  rdx => 0xb113d0bc9276b492
11:45:17  rax => 0xc4db1c0d0bc0421b
0x555555555433   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x555555555437   mov qword ptr [rax], rdx
11:45:17  0x80000000dd78 => 0xb113d0bc9276b492
11:45:17  rdx => 0xb113d0bc9276b492
0x55555555543a   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x55555555543e   mov rax, qword ptr [rax]
11:45:17  rax => 0xc4db1c0d0bc0421b
11:45:17  0x80000000dd70 => 0xc4db1c0d0bc0421b
0x555555555441   rol rax, 0x1c
11:45:17  rax => 0xd0bc0421bc4db1c0
0x555555555445   mov rdx, rax
11:45:17  rdx => 0xd0bc0421bc4db1c0
11:45:17  rax => 0xd0bc0421bc4db1c0
0x555555555448   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x55555555544c   mov qword ptr [rax], rdx
11:45:17  0x80000000dd70 => 0xd0bc0421bc4db1c0
11:45:17  rdx => 0xd0bc0421bc4db1c0
0x55555555544f   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x555555555453   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xb113d0bc9276b492
11:45:17  0x80000000dd78 => 0xb113d0bc9276b492
0x555555555456   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x55555555545a   mov rax, qword ptr [rax]
11:45:17  rax => 0x801dbd2c145c69b2
11:45:17  0x80000000dd68 => 0x801dbd2c145c69b2
0x55555555545d   add rdx, rax
11:45:17  rdx => 0x31318de8a6d31e44
11:45:17  rax => 0x801dbd2c145c69b2
0x555555555460   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x555555555464   mov qword ptr [rax], rdx
11:45:17  0x80000000dd78 => 0x31318de8a6d31e44
11:45:17  rdx => 0x31318de8a6d31e44
0x555555555467   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x55555555546b   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x801dbd2c145c69b2
11:45:17  0x80000000dd68 => 0x801dbd2c145c69b2
0x55555555546e   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x555555555472   add rax, 0x30
11:45:17  rax => 0x80000000dd68
0x555555555476   mov rax, qword ptr [rax]
11:45:17  rax => 0x801dbd2c145c69b2
11:45:17  0x80000000dd68 => 0x801dbd2c145c69b2
0x555555555479   add rdx, rax
11:45:17  rdx => 0x3b7a5828b8d364
11:45:17  rax => 0x801dbd2c145c69b2
0x55555555547c   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555480   mov qword ptr [rax], rdx
11:45:17  0x80000000dd68 => 0x3b7a5828b8d364
11:45:17  rdx => 0x3b7a5828b8d364
0x555555555483   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555487   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xe13579bdf02468ac
11:45:17  0x80000000dd58 => 0xe13579bdf02468ac
0x55555555548a   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x55555555548e   mov rax, qword ptr [rax]
11:45:17  rax => 0x31318de8a6d31e44
11:45:17  0x80000000dd78 => 0x31318de8a6d31e44
0x555555555491   xor rdx, rax
11:45:17  rdx => 0xd004f45556f776e8
11:45:17  rax => 0x31318de8a6d31e44
0x555555555494   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555498   mov qword ptr [rax], rdx
11:45:17  0x80000000dd58 => 0xd004f45556f776e8
11:45:17  rdx => 0xd004f45556f776e8
0x55555555549b   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x55555555549f   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xd0bc0421bc4db1c0
11:45:17  0x80000000dd70 => 0xd0bc0421bc4db1c0
0x5555555554a2   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x5555555554a6   mov rax, qword ptr [rax]
11:45:17  rax => 0x3b7a5828b8d364
11:45:17  0x80000000dd68 => 0x3b7a5828b8d364
0x5555555554a9   xor rdx, rax
11:45:17  rdx => 0xd0877e7994f562a4
11:45:17  rax => 0x3b7a5828b8d364
0x5555555554ac   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x5555555554b0   mov qword ptr [rax], rdx
11:45:17  0x80000000dd70 => 0xd0877e7994f562a4
11:45:17  rdx => 0xd0877e7994f562a4
0x5555555554b3   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x5555555554b7   mov rax, qword ptr [rax]
11:45:17  rax => 0x3b7a5828b8d364
11:45:17  0x80000000dd68 => 0x3b7a5828b8d364
0x5555555554ba   ror rax, 0x19
11:45:17  rax => 0x5c69b2001dbd2c14
0x5555555554be   mov rdx, rax
11:45:17  rdx => 0x5c69b2001dbd2c14
11:45:17  rax => 0x5c69b2001dbd2c14
0x5555555554c1   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x5555555554c5   mov qword ptr [rax], rdx
11:45:17  0x80000000dd68 => 0x5c69b2001dbd2c14
11:45:17  rdx => 0x5c69b2001dbd2c14
0x5555555554c8   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x5555555554cc   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xd0877e7994f562a4
11:45:17  0x80000000dd70 => 0xd0877e7994f562a4
0x5555555554cf   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555554d3   mov rax, qword ptr [rax]
11:45:17  rax => 0x6f882a6c0d195c79
11:45:17  0x80000000dd60 => 0x6f882a6c0d195c79
0x5555555554d6   add rdx, rax
11:45:17  rdx => 0x400fa8e5a20ebf1d
11:45:17  rax => 0x6f882a6c0d195c79
0x5555555554d9   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x5555555554dd   mov qword ptr [rax], rdx
11:45:17  0x80000000dd70 => 0x400fa8e5a20ebf1d
11:45:17  rdx => 0x400fa8e5a20ebf1d
0x5555555554e0   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555554e4   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x6f882a6c0d195c79
11:45:17  0x80000000dd60 => 0x6f882a6c0d195c79
0x5555555554e7   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x5555555554eb   add rax, 0x38
11:45:17  rax => 0x80000000dd70
0x5555555554ef   mov rax, qword ptr [rax]
11:45:17  rax => 0x400fa8e5a20ebf1d
11:45:17  0x80000000dd70 => 0x400fa8e5a20ebf1d
0x5555555554f2   add rdx, rax
11:45:17  rdx => 0xaf97d351af281b96
11:45:17  rax => 0x400fa8e5a20ebf1d
0x5555555554f5   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555554f9   mov qword ptr [rax], rdx
11:45:17  0x80000000dd60 => 0xaf97d351af281b96
11:45:17  rdx => 0xaf97d351af281b96
0x5555555554fc   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555500   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x68ace13579bdf024
11:45:17  0x80000000dd50 => 0x68ace13579bdf024
0x555555555503   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x555555555507   mov rax, qword ptr [rax]
11:45:17  rax => 0x400fa8e5a20ebf1d
11:45:17  0x80000000dd70 => 0x400fa8e5a20ebf1d
0x55555555550a   xor rdx, rax
11:45:17  rdx => 0x28a349d0dbb34f39
11:45:17  rax => 0x400fa8e5a20ebf1d
0x55555555550d   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555511   mov qword ptr [rax], rdx
11:45:17  0x80000000dd50 => 0x28a349d0dbb34f39
11:45:17  rdx => 0x28a349d0dbb34f39
0x555555555514   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555518   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x5c69b2001dbd2c14
11:45:17  0x80000000dd68 => 0x5c69b2001dbd2c14
0x55555555551b   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x55555555551f   mov rax, qword ptr [rax]
11:45:17  rax => 0xaf97d351af281b96
11:45:17  0x80000000dd60 => 0xaf97d351af281b96
0x555555555522   xor rdx, rax
11:45:17  rdx => 0xf3fe6151b2953782
11:45:17  rax => 0xaf97d351af281b96
0x555555555525   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555529   mov qword ptr [rax], rdx
11:45:17  0x80000000dd68 => 0xf3fe6151b2953782
11:45:17  rdx => 0xf3fe6151b2953782
0x55555555552c   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x555555555530   mov rax, qword ptr [rax]
11:45:17  rax => 0xaf97d351af281b96
11:45:17  0x80000000dd60 => 0xaf97d351af281b96
0x555555555533   ror rax, 7
11:45:17  rax => 0x2d5f2fa6a35e5037
0x555555555537   mov rdx, rax
11:45:17  rdx => 0x2d5f2fa6a35e5037
11:45:17  rax => 0x2d5f2fa6a35e5037
0x55555555553a   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x55555555553e   mov qword ptr [rax], rdx
11:45:17  0x80000000dd60 => 0x2d5f2fa6a35e5037
11:45:17  rdx => 0x2d5f2fa6a35e5037
0x555555555541   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555545   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xf3fe6151b2953782
11:45:17  0x80000000dd68 => 0xf3fe6151b2953782
0x555555555548   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x55555555554c   mov rax, qword ptr [rax]
11:45:17  rax => 0xd004f45556f776e8
11:45:17  0x80000000dd58 => 0xd004f45556f776e8
0x55555555554f   add rdx, rax
11:45:17  rdx => 0xc40355a7098cae6a
11:45:17  rax => 0xd004f45556f776e8
0x555555555552   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555556   mov qword ptr [rax], rdx
11:45:17  0x80000000dd68 => 0xc40355a7098cae6a
11:45:17  rdx => 0xc40355a7098cae6a
0x555555555559   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x55555555555d   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xd004f45556f776e8
11:45:17  0x80000000dd58 => 0xd004f45556f776e8
0x555555555560   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x555555555564   add rax, 0x40
11:45:17  rax => 0x80000000dd78
0x555555555568   mov rax, qword ptr [rax]
11:45:17  rax => 0x31318de8a6d31e44
11:45:17  0x80000000dd78 => 0x31318de8a6d31e44
0x55555555556b   add rdx, rax
11:45:17  rdx => 0x136823dfdca952c
11:45:17  rax => 0x31318de8a6d31e44
0x55555555556e   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555572   mov qword ptr [rax], rdx
11:45:17  0x80000000dd58 => 0x136823dfdca952c
11:45:17  rdx => 0x136823dfdca952c
0x555555555575   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x555555555579   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x79bdf02468ace135
11:45:17  0x80000000dd48 => 0x79bdf02468ace135
0x55555555557c   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555580   mov rax, qword ptr [rax]
11:45:17  rax => 0xc40355a7098cae6a
11:45:17  0x80000000dd68 => 0xc40355a7098cae6a
0x555555555583   xor rdx, rax
11:45:17  rdx => 0xbdbea58361204f5f
11:45:17  rax => 0xc40355a7098cae6a
0x555555555586   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555558a   mov qword ptr [rax], rdx
11:45:17  0x80000000dd48 => 0xbdbea58361204f5f
11:45:17  rdx => 0xbdbea58361204f5f
0x55555555558d   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x555555555591   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x2d5f2fa6a35e5037
11:45:17  0x80000000dd60 => 0x2d5f2fa6a35e5037
0x555555555594   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555598   mov rax, qword ptr [rax]
11:45:17  rax => 0x136823dfdca952c
11:45:17  0x80000000dd58 => 0x136823dfdca952c
0x55555555559b   xor rdx, rax
11:45:17  rdx => 0x2c69ad9b5e94c51b
11:45:17  rax => 0x136823dfdca952c
0x55555555559e   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555555a2   mov qword ptr [rax], rdx
11:45:17  0x80000000dd60 => 0x2c69ad9b5e94c51b
11:45:17  rdx => 0x2c69ad9b5e94c51b
0x5555555555a5   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x5555555555a9   mov rax, qword ptr [rax]
11:45:17  rax => 0x136823dfdca952c
11:45:17  0x80000000dd58 => 0x136823dfdca952c
0x5555555555ac   ror rax, 9
11:45:17  rax => 0x96009b411efee54a
0x5555555555b0   mov rdx, rax
11:45:17  rdx => 0x96009b411efee54a
11:45:17  rax => 0x96009b411efee54a
0x5555555555b3   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x5555555555b7   mov qword ptr [rax], rdx
11:45:17  0x80000000dd58 => 0x96009b411efee54a
11:45:17  rdx => 0x96009b411efee54a
0x5555555555ba   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555555be   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x2c69ad9b5e94c51b
11:45:17  0x80000000dd60 => 0x2c69ad9b5e94c51b
0x5555555555c1   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x5555555555c5   mov rax, qword ptr [rax]
11:45:17  rax => 0x28a349d0dbb34f39
11:45:17  0x80000000dd50 => 0x28a349d0dbb34f39
0x5555555555c8   add rdx, rax
11:45:17  rdx => 0x550cf76c3a481454
11:45:17  rax => 0x28a349d0dbb34f39
0x5555555555cb   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555555cf   mov qword ptr [rax], rdx
11:45:17  0x80000000dd60 => 0x550cf76c3a481454
11:45:17  rdx => 0x550cf76c3a481454
0x5555555555d2   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x5555555555d6   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x28a349d0dbb34f39
11:45:17  0x80000000dd50 => 0x28a349d0dbb34f39
0x5555555555d9   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x5555555555dd   add rax, 0x48
11:45:17  rax => 0x80000000dd80
0x5555555555e1   mov rax, qword ptr [rax]
11:45:17  rax => 0x5af1979c2971f098
11:45:17  0x80000000dd80 => 0x5af1979c2971f098
0x5555555555e4   add rdx, rax
11:45:17  rdx => 0x8394e16d05253fd1
11:45:17  rax => 0x5af1979c2971f098
0x5555555555e7   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x5555555555eb   mov qword ptr [rax], rdx
11:45:17  0x80000000dd50 => 0x8394e16d05253fd1
11:45:17  rdx => 0x8394e16d05253fd1
0x5555555555ee   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555555f2   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x622978ac4b0b337a
11:45:17  0x80000000dd40 => 0x622978ac4b0b337a
0x5555555555f5   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555555f9   mov rax, qword ptr [rax]
11:45:17  rax => 0x550cf76c3a481454
11:45:17  0x80000000dd60 => 0x550cf76c3a481454
0x5555555555fc   xor rdx, rax
11:45:17  rdx => 0x37258fc07143272e
11:45:17  rax => 0x550cf76c3a481454
0x5555555555ff   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x555555555603   mov qword ptr [rax], rdx
11:45:17  0x80000000dd40 => 0x37258fc07143272e
11:45:17  rdx => 0x37258fc07143272e
0x555555555606   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x55555555560a   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x96009b411efee54a
11:45:17  0x80000000dd58 => 0x96009b411efee54a
0x55555555560d   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555611   mov rax, qword ptr [rax]
11:45:17  rax => 0x8394e16d05253fd1
11:45:17  0x80000000dd50 => 0x8394e16d05253fd1
0x555555555614   xor rdx, rax
11:45:17  rdx => 0x15947a2c1bdbda9b
11:45:17  rax => 0x8394e16d05253fd1
0x555555555617   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x55555555561b   mov qword ptr [rax], rdx
11:45:17  0x80000000dd58 => 0x15947a2c1bdbda9b
11:45:17  rdx => 0x15947a2c1bdbda9b
0x55555555561e   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555622   mov rax, qword ptr [rax]
11:45:17  rax => 0x8394e16d05253fd1
11:45:17  0x80000000dd50 => 0x8394e16d05253fd1
0x555555555625   ror rax, 0xa
11:45:17  rax => 0xf460e5385b41494f
0x555555555629   mov rdx, rax
11:45:17  rdx => 0xf460e5385b41494f
11:45:17  rax => 0xf460e5385b41494f
0x55555555562c   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555630   mov qword ptr [rax], rdx
11:45:17  0x80000000dd50 => 0xf460e5385b41494f
11:45:17  rdx => 0xf460e5385b41494f
0x555555555633   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555637   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x15947a2c1bdbda9b
11:45:17  0x80000000dd58 => 0x15947a2c1bdbda9b
0x55555555563a   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555563e   mov rax, qword ptr [rax]
11:45:17  rax => 0xbdbea58361204f5f
11:45:17  0x80000000dd48 => 0xbdbea58361204f5f
0x555555555641   add rdx, rax
11:45:17  rdx => 0xd3531faf7cfc29fa
11:45:17  rax => 0xbdbea58361204f5f
0x555555555644   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555648   mov qword ptr [rax], rdx
11:45:17  0x80000000dd58 => 0xd3531faf7cfc29fa
11:45:17  rdx => 0xd3531faf7cfc29fa
0x55555555564b   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555564f   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xbdbea58361204f5f
11:45:17  0x80000000dd48 => 0xbdbea58361204f5f
0x555555555652   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x555555555656   add rax, 0x50
11:45:17  rax => 0x80000000dd88
0x55555555565a   mov rax, qword ptr [rax]
11:45:17  rax => 0xa47511cd2125d442
11:45:17  0x80000000dd88 => 0xa47511cd2125d442
0x55555555565d   add rdx, rax
11:45:17  rdx => 0x6233b750824623a1
11:45:17  rax => 0xa47511cd2125d442
0x555555555660   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x555555555664   mov qword ptr [rax], rdx
11:45:17  0x80000000dd48 => 0x6233b750824623a1
11:45:17  rdx => 0x6233b750824623a1
0x555555555667   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x55555555566b   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x8958daf97472eee1
11:45:17  0x80000000dd98 => 0x8958daf97472eee1
0x55555555566e   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555672   mov rax, qword ptr [rax]
11:45:17  rax => 0xd3531faf7cfc29fa
11:45:17  0x80000000dd58 => 0xd3531faf7cfc29fa
0x555555555675   xor rdx, rax
11:45:17  rdx => 0x5a0bc556088ec71b
11:45:17  rax => 0xd3531faf7cfc29fa
0x555555555678   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x55555555567c   mov qword ptr [rax], rdx
11:45:17  0x80000000dd98 => 0x5a0bc556088ec71b
11:45:17  rdx => 0x5a0bc556088ec71b
0x55555555567f   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555683   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xf460e5385b41494f
11:45:17  0x80000000dd50 => 0xf460e5385b41494f
0x555555555686   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555568a   mov rax, qword ptr [rax]
11:45:17  rax => 0x6233b750824623a1
11:45:17  0x80000000dd48 => 0x6233b750824623a1
0x55555555568d   xor rdx, rax
11:45:17  rdx => 0x96535268d9076aee
11:45:17  rax => 0x6233b750824623a1
0x555555555690   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555694   mov qword ptr [rax], rdx
11:45:17  0x80000000dd50 => 0x96535268d9076aee
11:45:17  rdx => 0x96535268d9076aee
0x555555555697   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555569b   mov rax, qword ptr [rax]
11:45:17  rax => 0x6233b750824623a1
11:45:17  0x80000000dd48 => 0x6233b750824623a1
0x55555555569e   rol rax, 0x16
11:45:17  rax => 0xd4209188e8588ced
0x5555555556a2   mov rdx, rax
11:45:17  rdx => 0xd4209188e8588ced
11:45:17  rax => 0xd4209188e8588ced
0x5555555556a5   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x5555555556a9   mov qword ptr [rax], rdx
11:45:17  0x80000000dd48 => 0xd4209188e8588ced
11:45:17  rdx => 0xd4209188e8588ced
0x5555555556ac   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x5555555556b0   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x96535268d9076aee
11:45:17  0x80000000dd50 => 0x96535268d9076aee
0x5555555556b3   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555556b7   mov rax, qword ptr [rax]
11:45:17  rax => 0x37258fc07143272e
11:45:17  0x80000000dd40 => 0x37258fc07143272e
0x5555555556ba   add rdx, rax
11:45:17  rdx => 0xcd78e2294a4a921c
11:45:17  rax => 0x37258fc07143272e
0x5555555556bd   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x5555555556c1   mov qword ptr [rax], rdx
11:45:17  0x80000000dd50 => 0xcd78e2294a4a921c
11:45:17  rdx => 0xcd78e2294a4a921c
0x5555555556c4   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555556c8   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x37258fc07143272e
11:45:17  0x80000000dd40 => 0x37258fc07143272e
0x5555555556cb   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x5555555556cf   add rax, 0x58
11:45:17  rax => 0x80000000dd90
0x5555555556d3   mov rax, qword ptr [rax]
11:45:17  rax => 0x14be5c5a6d99866d
11:45:17  0x80000000dd90 => 0x14be5c5a6d99866d
0x5555555556d6   add rdx, rax
11:45:17  rdx => 0x4be3ec1adedcad9b
11:45:17  rax => 0x14be5c5a6d99866d
0x5555555556d9   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555556dd   mov qword ptr [rax], rdx
11:45:17  0x80000000dd40 => 0x4be3ec1adedcad9b
11:45:17  rdx => 0x4be3ec1adedcad9b
0x5555555556e0   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555556e4   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x14be5c5a6d99866d
11:45:17  0x80000000dd90 => 0x14be5c5a6d99866d
0x5555555556e7   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x5555555556eb   mov rax, qword ptr [rax]
11:45:17  rax => 0xcd78e2294a4a921c
11:45:17  0x80000000dd50 => 0xcd78e2294a4a921c
0x5555555556ee   xor rdx, rax
11:45:17  rdx => 0xd9c6be7327d31471
11:45:17  rax => 0xcd78e2294a4a921c
0x5555555556f1   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555556f5   mov qword ptr [rax], rdx
11:45:17  0x80000000dd90 => 0xd9c6be7327d31471
11:45:17  rdx => 0xd9c6be7327d31471
0x5555555556f8   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x5555555556fc   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xd4209188e8588ced
11:45:17  0x80000000dd48 => 0xd4209188e8588ced
0x5555555556ff   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x555555555703   mov rax, qword ptr [rax]
11:45:17  rax => 0x4be3ec1adedcad9b
11:45:17  0x80000000dd40 => 0x4be3ec1adedcad9b
0x555555555706   xor rdx, rax
11:45:17  rdx => 0x9fc37d9236842176
11:45:17  rax => 0x4be3ec1adedcad9b
0x555555555709   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555570d   mov qword ptr [rax], rdx
11:45:17  0x80000000dd48 => 0x9fc37d9236842176
11:45:17  rdx => 0x9fc37d9236842176
0x555555555710   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x555555555714   mov rax, qword ptr [rax]
11:45:17  rax => 0x4be3ec1adedcad9b
11:45:17  0x80000000dd40 => 0x4be3ec1adedcad9b
0x555555555717   ror rax, 0x12
11:45:17  rax => 0x2b66d2f8fb06b7b7
0x55555555571b   mov rdx, rax
11:45:17  rdx => 0x2b66d2f8fb06b7b7
11:45:17  rax => 0x2b66d2f8fb06b7b7
0x55555555571e   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x555555555722   mov qword ptr [rax], rdx
11:45:17  0x80000000dd40 => 0x2b66d2f8fb06b7b7
11:45:17  rdx => 0x2b66d2f8fb06b7b7
0x555555555725   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x555555555729   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x9fc37d9236842176
11:45:17  0x80000000dd48 => 0x9fc37d9236842176
0x55555555572c   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x555555555730   mov rax, qword ptr [rax]
11:45:17  rax => 0x5a0bc556088ec71b
11:45:17  0x80000000dd98 => 0x5a0bc556088ec71b
0x555555555733   add rdx, rax
11:45:17  rdx => 0xf9cf42e83f12e891
11:45:17  rax => 0x5a0bc556088ec71b
0x555555555736   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555573a   mov qword ptr [rax], rdx
11:45:17  0x80000000dd48 => 0xf9cf42e83f12e891
11:45:17  rdx => 0xf9cf42e83f12e891
0x55555555573d   nop 
0x55555555573e   pop rbp
11:45:17  rbp => 0x80000000ddb8
0x55555555573f   ret 
0x5555555558b6   add rsp, 0x40
11:45:17  rsp => 0x80000000dd28
0x5555555558ba   add qword ptr [rbp - 8], 1
11:45:17  0x80000000ddb0 => 0x1
0x5555555558bf   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x14
11:45:17  0x80000000dda0 => 0x14
0x5555555558c3   shr rax, 3
11:45:17  rax => 0x2
0x5555555558c7   cmp qword ptr [rbp - 8], rax
11:45:17  0x80000000ddb0 => 0x1
11:45:17  rax => 0x2
0x5555555558cb   jb 0x55555555581a
0x55555555581a   mov qword ptr [rbp - 0x80], 0
11:45:17  0x80000000dd38 => 0x0
0x555555555822   mov dword ptr [rbp - 0xc], 0
11:45:17  0x80000000ddac => 0x100000000
0x555555555829   jmp 0x555555555869
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x100000000
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0x0
11:45:17  0x80000000dd38 => 0x0
0x55555555582f   shl rax, 8
11:45:17  rax => 0x0
0x555555555833   mov rdx, rax
11:45:17  rdx => 0x0
11:45:17  rax => 0x0
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x1
11:45:17  0x80000000ddb0 => 0x1
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x8
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x0
11:45:17  0x80000000ddac => 0x100000000
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0x8
11:45:17  rax => 0x0
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd80
11:45:17  rcx => 0x8
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0x98
11:45:17  0x80000000dd80 => 0x5af1979c2971f098
0x555555555857   movsx rax, al
11:45:17  rax => 0xffffffffffffff98
11:45:17  al => 0x98
0x55555555585b   movzx eax, al
11:45:17  eax => 0x98
11:45:17  al => 0x98
0x55555555585e   or rax, rdx
11:45:17  rax => 0x98
11:45:17  rdx => 0x0
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0x98
11:45:17  rax => 0x98
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x100000001
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x100000001
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0x98
11:45:17  0x80000000dd38 => 0x98
0x55555555582f   shl rax, 8
11:45:17  rax => 0x9800
0x555555555833   mov rdx, rax
11:45:17  rdx => 0x9800
11:45:17  rax => 0x9800
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x1
11:45:17  0x80000000ddb0 => 0x1
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x8
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x1
11:45:17  0x80000000ddac => 0x100000001
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0x9
11:45:17  rax => 0x1
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd81
11:45:17  rcx => 0x9
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0xf0
11:45:17  0x80000000dd81 => 0x425af1979c2971f0
0x555555555857   movsx rax, al
11:45:17  rax => 0xfffffffffffffff0
11:45:17  al => 0xf0
0x55555555585b   movzx eax, al
11:45:17  eax => 0xf0
11:45:17  al => 0xf0
0x55555555585e   or rax, rdx
11:45:17  rax => 0x98f0
11:45:17  rdx => 0x9800
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0x98f0
11:45:17  rax => 0x98f0
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x100000002
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x100000002
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0x98f0
11:45:17  0x80000000dd38 => 0x98f0
0x55555555582f   shl rax, 8
11:45:17  rax => 0x98f000
0x555555555833   mov rdx, rax
11:45:17  rdx => 0x98f000
11:45:17  rax => 0x98f000
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x1
11:45:17  0x80000000ddb0 => 0x1
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x8
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x2
11:45:17  0x80000000ddac => 0x100000002
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0xa
11:45:17  rax => 0x2
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd82
11:45:17  rcx => 0xa
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0x71
11:45:17  0x80000000dd82 => 0xd4425af1979c2971
0x555555555857   movsx rax, al
11:45:17  rax => 0x71
11:45:17  al => 0x71
0x55555555585b   movzx eax, al
11:45:17  eax => 0x71
11:45:17  al => 0x71
0x55555555585e   or rax, rdx
11:45:17  rax => 0x98f071
11:45:17  rdx => 0x98f000
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0x98f071
11:45:17  rax => 0x98f071
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x100000003
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x100000003
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0x98f071
11:45:17  0x80000000dd38 => 0x98f071
0x55555555582f   shl rax, 8
11:45:17  rax => 0x98f07100
0x555555555833   mov rdx, rax
11:45:17  rdx => 0x98f07100
11:45:17  rax => 0x98f07100
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x1
11:45:17  0x80000000ddb0 => 0x1
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x8
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x3
11:45:17  0x80000000ddac => 0x100000003
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0xb
11:45:17  rax => 0x3
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd83
11:45:17  rcx => 0xb
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0x29
11:45:17  0x80000000dd83 => 0x25d4425af1979c29
0x555555555857   movsx rax, al
11:45:17  rax => 0x29
11:45:17  al => 0x29
0x55555555585b   movzx eax, al
11:45:17  eax => 0x29
11:45:17  al => 0x29
0x55555555585e   or rax, rdx
11:45:17  rax => 0x98f07129
11:45:17  rdx => 0x98f07100
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0x98f07129
11:45:17  rax => 0x98f07129
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x100000004
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x100000004
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0x98f07129
11:45:17  0x80000000dd38 => 0x98f07129
0x55555555582f   shl rax, 8
11:45:17  rax => 0x98f0712900
0x555555555833   mov rdx, rax
11:45:17  rdx => 0x98f0712900
11:45:17  rax => 0x98f0712900
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x1
11:45:17  0x80000000ddb0 => 0x1
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x8
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x4
11:45:17  0x80000000ddac => 0x100000004
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0xc
11:45:17  rax => 0x4
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd84
11:45:17  rcx => 0xc
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0x9c
11:45:17  0x80000000dd84 => 0x2125d4425af1979c
0x555555555857   movsx rax, al
11:45:17  rax => 0xffffffffffffff9c
11:45:17  al => 0x9c
0x55555555585b   movzx eax, al
11:45:17  eax => 0x9c
11:45:17  al => 0x9c
0x55555555585e   or rax, rdx
11:45:17  rax => 0x98f071299c
11:45:17  rdx => 0x98f0712900
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0x98f071299c
11:45:17  rax => 0x98f071299c
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x100000005
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x100000005
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0x98f071299c
11:45:17  0x80000000dd38 => 0x98f071299c
0x55555555582f   shl rax, 8
11:45:17  rax => 0x98f071299c00
0x555555555833   mov rdx, rax
11:45:17  rdx => 0x98f071299c00
11:45:17  rax => 0x98f071299c00
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x1
11:45:17  0x80000000ddb0 => 0x1
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x8
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x5
11:45:17  0x80000000ddac => 0x100000005
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0xd
11:45:17  rax => 0x5
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd85
11:45:17  rcx => 0xd
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0x97
11:45:17  0x80000000dd85 => 0xcd2125d4425af197
0x555555555857   movsx rax, al
11:45:17  rax => 0xffffffffffffff97
11:45:17  al => 0x97
0x55555555585b   movzx eax, al
11:45:17  eax => 0x97
11:45:17  al => 0x97
0x55555555585e   or rax, rdx
11:45:17  rax => 0x98f071299c97
11:45:17  rdx => 0x98f071299c00
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0x98f071299c97
11:45:17  rax => 0x98f071299c97
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x100000006
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x100000006
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0x98f071299c97
11:45:17  0x80000000dd38 => 0x98f071299c97
0x55555555582f   shl rax, 8
11:45:17  rax => 0x98f071299c9700
0x555555555833   mov rdx, rax
11:45:17  rdx => 0x98f071299c9700
11:45:17  rax => 0x98f071299c9700
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x1
11:45:17  0x80000000ddb0 => 0x1
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x8
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x6
11:45:17  0x80000000ddac => 0x100000006
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0xe
11:45:17  rax => 0x6
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd86
11:45:17  rcx => 0xe
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0xf1
11:45:17  0x80000000dd86 => 0x11cd2125d4425af1
0x555555555857   movsx rax, al
11:45:17  rax => 0xfffffffffffffff1
11:45:17  al => 0xf1
0x55555555585b   movzx eax, al
11:45:17  eax => 0xf1
11:45:17  al => 0xf1
0x55555555585e   or rax, rdx
11:45:17  rax => 0x98f071299c97f1
11:45:17  rdx => 0x98f071299c9700
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0x98f071299c97f1
11:45:17  rax => 0x98f071299c97f1
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x100000007
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x100000007
0x55555555586d   jle 0x55555555582b
0x55555555582b   mov rax, qword ptr [rbp - 0x80]
11:45:17  rax => 0x98f071299c97f1
11:45:17  0x80000000dd38 => 0x98f071299c97f1
0x55555555582f   shl rax, 8
11:45:17  rax => 0x98f071299c97f100
0x555555555833   mov rdx, rax
11:45:17  rdx => 0x98f071299c97f100
11:45:17  rax => 0x98f071299c97f100
0x555555555836   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x1
11:45:17  0x80000000ddb0 => 0x1
0x55555555583a   lea rcx, [rax*8]
11:45:17  rcx => 0x8
0x555555555842   mov eax, dword ptr [rbp - 0xc]
11:45:17  eax => 0x7
11:45:17  0x80000000ddac => 0x100000007
0x555555555845   cdqe 
0x555555555847   add rcx, rax
11:45:17  rcx => 0xf
11:45:17  rax => 0x7
0x55555555584a   mov rax, qword ptr [rbp - 0x88]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dd30 => 0x80000000dd78
0x555555555851   add rax, rcx
11:45:17  rax => 0x80000000dd87
11:45:17  rcx => 0xf
0x555555555854   movzx eax, byte ptr [rax]
11:45:17  eax => 0x5a
11:45:17  0x80000000dd87 => 0x7511cd2125d4425a
0x555555555857   movsx rax, al
11:45:17  rax => 0x5a
11:45:17  al => 0x5a
0x55555555585b   movzx eax, al
11:45:17  eax => 0x5a
11:45:17  al => 0x5a
0x55555555585e   or rax, rdx
11:45:17  rax => 0x98f071299c97f15a
11:45:17  rdx => 0x98f071299c97f100
0x555555555861   mov qword ptr [rbp - 0x80], rax
11:45:17  0x80000000dd38 => 0x98f071299c97f15a
11:45:17  rax => 0x98f071299c97f15a
0x555555555865   add dword ptr [rbp - 0xc], 1
11:45:17  0x80000000ddac => 0x100000008
0x555555555869   cmp dword ptr [rbp - 0xc], 7
11:45:17  0x80000000ddac => 0x100000008
0x55555555586d   jle 0x55555555582b
0x55555555586f   lea r9, [rbp - 0x40]
11:45:17  r9 => 0x80000000dd78
11:45:17  0x80000000dd78 => 0x31318de8a6d31e44
0x555555555873   lea r8, [rbp - 0x38]
11:45:17  r8 => 0x80000000dd80
11:45:17  0x80000000dd80 => 0x5af1979c2971f098
0x555555555877   lea rcx, [rbp - 0x30]
11:45:17  rcx => 0x80000000dd88
11:45:17  0x80000000dd88 => 0xa47511cd2125d442
0x55555555587b   lea rdx, [rbp - 0x28]
11:45:17  rdx => 0x80000000dd90
11:45:17  0x80000000dd90 => 0xd9c6be7327d31471
0x55555555587f   lea rsi, [rbp - 0x20]
11:45:17  rsi => 0x80000000dd98
11:45:17  0x80000000dd98 => 0x5a0bc556088ec71b
0x555555555883   lea rax, [rbp - 0x80]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dd38 => 0x98f071299c97f15a
0x555555555887   sub rsp, 8
11:45:17  rsp => 0x80000000dd20
0x55555555588b   lea rdi, [rbp - 0x78]
11:45:17  rdi => 0x80000000dd40
11:45:17  0x80000000dd40 => 0x2b66d2f8fb06b7b7
0x55555555588f   push rdi
11:45:17  rdi => 0x80000000dd40
0x555555555890   lea rdi, [rbp - 0x70]
11:45:17  rdi => 0x80000000dd48
11:45:17  0x80000000dd48 => 0xf9cf42e83f12e891
0x555555555894   push rdi
11:45:17  rdi => 0x80000000dd48
0x555555555895   lea rdi, [rbp - 0x68]
11:45:17  rdi => 0x80000000dd50
11:45:17  0x80000000dd50 => 0xcd78e2294a4a921c
0x555555555899   push rdi
11:45:17  rdi => 0x80000000dd50
0x55555555589a   lea rdi, [rbp - 0x60]
11:45:17  rdi => 0x80000000dd58
11:45:17  0x80000000dd58 => 0xd3531faf7cfc29fa
0x55555555589e   push rdi
11:45:17  rdi => 0x80000000dd58
0x55555555589f   lea rdi, [rbp - 0x58]
11:45:17  rdi => 0x80000000dd60
11:45:17  0x80000000dd60 => 0x550cf76c3a481454
0x5555555558a3   push rdi
11:45:17  rdi => 0x80000000dd60
0x5555555558a4   lea rdi, [rbp - 0x50]
11:45:17  rdi => 0x80000000dd68
11:45:17  0x80000000dd68 => 0xc40355a7098cae6a
0x5555555558a8   push rdi
11:45:17  rdi => 0x80000000dd68
0x5555555558a9   lea rdi, [rbp - 0x48]
11:45:17  rdi => 0x80000000dd70
11:45:17  0x80000000dd70 => 0x400fa8e5a20ebf1d
0x5555555558ad   push rdi
11:45:17  rdi => 0x80000000dd70
0x5555555558ae   mov rdi, rax
11:45:17  rdi => 0x80000000dd38
11:45:17  rax => 0x80000000dd38
0x5555555558b1   call 0x555555555179
0x555555555179   push rbp
11:45:17  rbp => 0x80000000ddb8
0x55555555517a   mov rbp, rsp
11:45:17  rbp => 0x80000000dcd8
11:45:17  rsp => 0x80000000dcd8
0x55555555517d   mov qword ptr [rbp - 8], rdi
11:45:17  0x80000000dcd0 => 0x80000000dd38
11:45:17  rdi => 0x80000000dd38
0x555555555181   mov qword ptr [rbp - 0x10], rsi
11:45:17  0x80000000dcc8 => 0x80000000dd98
11:45:17  rsi => 0x80000000dd98
0x555555555185   mov qword ptr [rbp - 0x18], rdx
11:45:17  0x80000000dcc0 => 0x80000000dd90
11:45:17  rdx => 0x80000000dd90
0x555555555189   mov qword ptr [rbp - 0x20], rcx
11:45:17  0x80000000dcb8 => 0x80000000dd88
11:45:17  rcx => 0x80000000dd88
0x55555555518d   mov qword ptr [rbp - 0x28], r8
11:45:17  0x80000000dcb0 => 0x80000000dd80
11:45:17  r8 => 0x80000000dd80
0x555555555191   mov qword ptr [rbp - 0x30], r9
11:45:17  0x80000000dca8 => 0x80000000dd78
11:45:17  r9 => 0x80000000dd78
0x555555555195   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x555555555199   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x5a0bc556088ec71b
11:45:17  0x80000000dd98 => 0x5a0bc556088ec71b
0x55555555519c   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x5555555551a0   mov rax, qword ptr [rax]
11:45:17  rax => 0x98f071299c97f15a
11:45:17  0x80000000dd38 => 0x98f071299c97f15a
0x5555555551a3   add rdx, rax
11:45:17  rdx => 0xf2fc367fa526b875
11:45:17  rax => 0x98f071299c97f15a
0x5555555551a6   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x5555555551aa   mov qword ptr [rax], rdx
11:45:17  0x80000000dd98 => 0xf2fc367fa526b875
11:45:17  rdx => 0xf2fc367fa526b875
0x5555555551ad   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x5555555551b1   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xa47511cd2125d442
11:45:17  0x80000000dd88 => 0xa47511cd2125d442
0x5555555551b4   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x5555555551b8   mov rax, qword ptr [rax]
11:45:17  rax => 0xf9cf42e83f12e891
11:45:17  0x80000000dd48 => 0xf9cf42e83f12e891
0x5555555551bb   xor rdx, rax
11:45:17  rdx => 0x5dba53251e373cd3
11:45:17  rax => 0xf9cf42e83f12e891
0x5555555551be   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x5555555551c2   mov qword ptr [rax], rdx
11:45:17  0x80000000dd88 => 0x5dba53251e373cd3
11:45:17  rdx => 0x5dba53251e373cd3
0x5555555551c5   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555551c9   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x2b66d2f8fb06b7b7
11:45:17  0x80000000dd40 => 0x2b66d2f8fb06b7b7
0x5555555551cc   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x5555555551d0   mov rax, qword ptr [rax]
11:45:17  rax => 0xf2fc367fa526b875
11:45:17  0x80000000dd98 => 0xf2fc367fa526b875
0x5555555551d3   xor rdx, rax
11:45:17  rdx => 0xd99ae4875e200fc2
11:45:17  rax => 0xf2fc367fa526b875
0x5555555551d6   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555551da   mov qword ptr [rax], rdx
11:45:17  0x80000000dd40 => 0xd99ae4875e200fc2
11:45:17  rdx => 0xd99ae4875e200fc2
0x5555555551dd   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x5555555551e1   mov rax, qword ptr [rax]
11:45:17  rax => 0xf2fc367fa526b875
11:45:17  0x80000000dd98 => 0xf2fc367fa526b875
0x5555555551e4   rol rax, 0xb
11:45:17  rax => 0xe1b3fd2935c3af97
0x5555555551e8   mov rdx, rax
11:45:17  rdx => 0xe1b3fd2935c3af97
11:45:17  rax => 0xe1b3fd2935c3af97
0x5555555551eb   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x5555555551ef   mov qword ptr [rax], rdx
11:45:17  0x80000000dd98 => 0xe1b3fd2935c3af97
11:45:17  rdx => 0xe1b3fd2935c3af97
0x5555555551f2   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555551f6   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xd99ae4875e200fc2
11:45:17  0x80000000dd40 => 0xd99ae4875e200fc2
0x5555555551f9   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555551fd   mov rax, qword ptr [rax]
11:45:17  rax => 0xd9c6be7327d31471
11:45:17  0x80000000dd90 => 0xd9c6be7327d31471
0x555555555200   add rdx, rax
11:45:17  rdx => 0xb361a2fa85f32433
11:45:17  rax => 0xd9c6be7327d31471
0x555555555203   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x555555555207   mov qword ptr [rax], rdx
11:45:17  0x80000000dd40 => 0xb361a2fa85f32433
11:45:17  rdx => 0xb361a2fa85f32433
0x55555555520a   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x55555555520e   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xd9c6be7327d31471
11:45:17  0x80000000dd90 => 0xd9c6be7327d31471
0x555555555211   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x555555555215   add rax, 8
11:45:17  rax => 0x80000000dd40
0x555555555219   mov rax, qword ptr [rax]
11:45:17  rax => 0xb361a2fa85f32433
11:45:17  0x80000000dd40 => 0xb361a2fa85f32433
0x55555555521c   add rdx, rax
11:45:17  rdx => 0x8d28616dadc638a4
11:45:17  rax => 0xb361a2fa85f32433
0x55555555521f   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x555555555223   mov qword ptr [rax], rdx
11:45:17  0x80000000dd90 => 0x8d28616dadc638a4
11:45:17  rdx => 0x8d28616dadc638a4
0x555555555226   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x55555555522a   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x5af1979c2971f098
11:45:17  0x80000000dd80 => 0x5af1979c2971f098
0x55555555522d   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x555555555231   mov rax, qword ptr [rax]
11:45:17  rax => 0xb361a2fa85f32433
11:45:17  0x80000000dd40 => 0xb361a2fa85f32433
0x555555555234   xor rdx, rax
11:45:17  rdx => 0xe9903566ac82d4ab
11:45:17  rax => 0xb361a2fa85f32433
0x555555555237   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x55555555523b   mov qword ptr [rax], rdx
11:45:17  0x80000000dd80 => 0xe9903566ac82d4ab
11:45:17  rdx => 0xe9903566ac82d4ab
0x55555555523e   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x555555555242   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xe1b3fd2935c3af97
11:45:17  0x80000000dd98 => 0xe1b3fd2935c3af97
0x555555555245   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x555555555249   mov rax, qword ptr [rax]
11:45:17  rax => 0x8d28616dadc638a4
11:45:17  0x80000000dd90 => 0x8d28616dadc638a4
0x55555555524c   xor rdx, rax
11:45:17  rdx => 0x6c9b9c4498059733
11:45:17  rax => 0x8d28616dadc638a4
0x55555555524f   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x555555555253   mov qword ptr [rax], rdx
11:45:17  0x80000000dd98 => 0x6c9b9c4498059733
11:45:17  rdx => 0x6c9b9c4498059733
0x555555555256   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x55555555525a   mov rax, qword ptr [rax]
11:45:17  rax => 0x8d28616dadc638a4
11:45:17  0x80000000dd90 => 0x8d28616dadc638a4
0x55555555525d   rol rax, 0x20
11:45:17  rax => 0xadc638a48d28616d
0x555555555261   mov rdx, rax
11:45:17  rdx => 0xadc638a48d28616d
11:45:17  rax => 0xadc638a48d28616d
0x555555555264   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x555555555268   mov qword ptr [rax], rdx
11:45:17  0x80000000dd90 => 0xadc638a48d28616d
11:45:17  rdx => 0xadc638a48d28616d
0x55555555526b   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x55555555526f   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x6c9b9c4498059733
11:45:17  0x80000000dd98 => 0x6c9b9c4498059733
0x555555555272   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x555555555276   mov rax, qword ptr [rax]
11:45:17  rax => 0x5dba53251e373cd3
11:45:17  0x80000000dd88 => 0x5dba53251e373cd3
0x555555555279   add rdx, rax
11:45:17  rdx => 0xca55ef69b63cd406
11:45:17  rax => 0x5dba53251e373cd3
0x55555555527c   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x555555555280   mov qword ptr [rax], rdx
11:45:17  0x80000000dd98 => 0xca55ef69b63cd406
11:45:17  rdx => 0xca55ef69b63cd406
0x555555555283   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x555555555287   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x5dba53251e373cd3
11:45:17  0x80000000dd88 => 0x5dba53251e373cd3
0x55555555528a   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x55555555528e   add rax, 0x10
11:45:17  rax => 0x80000000dd48
0x555555555292   mov rax, qword ptr [rax]
11:45:17  rax => 0xf9cf42e83f12e891
11:45:17  0x80000000dd48 => 0xf9cf42e83f12e891
0x555555555295   add rdx, rax
11:45:17  rdx => 0x5789960d5d4a2564
11:45:17  rax => 0xf9cf42e83f12e891
0x555555555298   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x55555555529c   mov qword ptr [rax], rdx
11:45:17  0x80000000dd88 => 0x5789960d5d4a2564
11:45:17  rdx => 0x5789960d5d4a2564
0x55555555529f   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x5555555552a3   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x31318de8a6d31e44
11:45:17  0x80000000dd78 => 0x31318de8a6d31e44
0x5555555552a6   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x5555555552aa   mov rax, qword ptr [rax]
11:45:17  rax => 0xca55ef69b63cd406
11:45:17  0x80000000dd98 => 0xca55ef69b63cd406
0x5555555552ad   xor rdx, rax
11:45:17  rdx => 0xfb64628110efca42
11:45:17  rax => 0xca55ef69b63cd406
0x5555555552b0   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x5555555552b4   mov qword ptr [rax], rdx
11:45:17  0x80000000dd78 => 0xfb64628110efca42
11:45:17  rdx => 0xfb64628110efca42
0x5555555552b7   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555552bb   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xadc638a48d28616d
11:45:17  0x80000000dd90 => 0xadc638a48d28616d
0x5555555552be   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x5555555552c2   mov rax, qword ptr [rax]
11:45:17  rax => 0x5789960d5d4a2564
11:45:17  0x80000000dd88 => 0x5789960d5d4a2564
0x5555555552c5   xor rdx, rax
11:45:17  rdx => 0xfa4faea9d0624409
11:45:17  rax => 0x5789960d5d4a2564
0x5555555552c8   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555552cc   mov qword ptr [rax], rdx
11:45:17  0x80000000dd90 => 0xfa4faea9d0624409
11:45:17  rdx => 0xfa4faea9d0624409
0x5555555552cf   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x5555555552d3   mov rax, qword ptr [rax]
11:45:17  rax => 0x5789960d5d4a2564
11:45:17  0x80000000dd88 => 0x5789960d5d4a2564
0x5555555552d6   ror rax, 0x15
11:45:17  rax => 0x512b22bc4cb06aea
0x5555555552da   mov rdx, rax
11:45:17  rdx => 0x512b22bc4cb06aea
11:45:17  rax => 0x512b22bc4cb06aea
0x5555555552dd   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x5555555552e1   mov qword ptr [rax], rdx
11:45:17  0x80000000dd88 => 0x512b22bc4cb06aea
11:45:17  rdx => 0x512b22bc4cb06aea
0x5555555552e4   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555552e8   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xfa4faea9d0624409
11:45:17  0x80000000dd90 => 0xfa4faea9d0624409
0x5555555552eb   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x5555555552ef   mov rax, qword ptr [rax]
11:45:17  rax => 0xe9903566ac82d4ab
11:45:17  0x80000000dd80 => 0xe9903566ac82d4ab
0x5555555552f2   add rdx, rax
11:45:17  rdx => 0xe3dfe4107ce518b4
11:45:17  rax => 0xe9903566ac82d4ab
0x5555555552f5   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555552f9   mov qword ptr [rax], rdx
11:45:17  0x80000000dd90 => 0xe3dfe4107ce518b4
11:45:17  rdx => 0xe3dfe4107ce518b4
0x5555555552fc   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x555555555300   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xe9903566ac82d4ab
11:45:17  0x80000000dd80 => 0xe9903566ac82d4ab
0x555555555303   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x555555555307   add rax, 0x18
11:45:17  rax => 0x80000000dd50
0x55555555530b   mov rax, qword ptr [rax]
11:45:17  rax => 0xcd78e2294a4a921c
11:45:17  0x80000000dd50 => 0xcd78e2294a4a921c
0x55555555530e   add rdx, rax
11:45:17  rdx => 0xb709178ff6cd66c7
11:45:17  rax => 0xcd78e2294a4a921c
0x555555555311   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x555555555315   mov qword ptr [rax], rdx
11:45:17  0x80000000dd80 => 0xb709178ff6cd66c7
11:45:17  rdx => 0xb709178ff6cd66c7
0x555555555318   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x55555555531c   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x400fa8e5a20ebf1d
11:45:17  0x80000000dd70 => 0x400fa8e5a20ebf1d
0x55555555531f   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x555555555323   mov rax, qword ptr [rax]
11:45:17  rax => 0xe3dfe4107ce518b4
11:45:17  0x80000000dd90 => 0xe3dfe4107ce518b4
0x555555555326   xor rdx, rax
11:45:17  rdx => 0xa3d04cf5deeba7a9
11:45:17  rax => 0xe3dfe4107ce518b4
0x555555555329   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x55555555532d   mov qword ptr [rax], rdx
11:45:17  0x80000000dd70 => 0xa3d04cf5deeba7a9
11:45:17  rdx => 0xa3d04cf5deeba7a9
0x555555555330   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x555555555334   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x512b22bc4cb06aea
11:45:17  0x80000000dd88 => 0x512b22bc4cb06aea
0x555555555337   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x55555555533b   mov rax, qword ptr [rax]
11:45:17  rax => 0xb709178ff6cd66c7
11:45:17  0x80000000dd80 => 0xb709178ff6cd66c7
0x55555555533e   xor rdx, rax
11:45:17  rdx => 0xe6223533ba7d0c2d
11:45:17  rax => 0xb709178ff6cd66c7
0x555555555341   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x555555555345   mov qword ptr [rax], rdx
11:45:17  0x80000000dd88 => 0xe6223533ba7d0c2d
11:45:17  rdx => 0xe6223533ba7d0c2d
0x555555555348   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x55555555534c   mov rax, qword ptr [rax]
11:45:17  rax => 0xb709178ff6cd66c7
11:45:17  0x80000000dd80 => 0xb709178ff6cd66c7
0x55555555534f   rol rax, 0x1f
11:45:17  rax => 0xfb66b363db848bc7
0x555555555353   mov rdx, rax
11:45:17  rdx => 0xfb66b363db848bc7
11:45:17  rax => 0xfb66b363db848bc7
0x555555555356   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x55555555535a   mov qword ptr [rax], rdx
11:45:17  0x80000000dd80 => 0xfb66b363db848bc7
11:45:17  rdx => 0xfb66b363db848bc7
0x55555555535d   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x555555555361   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xe6223533ba7d0c2d
11:45:17  0x80000000dd88 => 0xe6223533ba7d0c2d
0x555555555364   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x555555555368   mov rax, qword ptr [rax]
11:45:17  rax => 0xfb64628110efca42
11:45:17  0x80000000dd78 => 0xfb64628110efca42
0x55555555536b   add rdx, rax
11:45:17  rdx => 0xe18697b4cb6cd66f
11:45:17  rax => 0xfb64628110efca42
0x55555555536e   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x555555555372   mov qword ptr [rax], rdx
11:45:17  0x80000000dd88 => 0xe18697b4cb6cd66f
11:45:17  rdx => 0xe18697b4cb6cd66f
0x555555555375   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x555555555379   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xfb64628110efca42
11:45:17  0x80000000dd78 => 0xfb64628110efca42
0x55555555537c   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x555555555380   add rax, 0x20
11:45:17  rax => 0x80000000dd58
0x555555555384   mov rax, qword ptr [rax]
11:45:17  rax => 0xd3531faf7cfc29fa
11:45:17  0x80000000dd58 => 0xd3531faf7cfc29fa
0x555555555387   add rdx, rax
11:45:17  rdx => 0xceb782308debf43c
11:45:17  rax => 0xd3531faf7cfc29fa
0x55555555538a   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x55555555538e   mov qword ptr [rax], rdx
11:45:17  0x80000000dd78 => 0xceb782308debf43c
11:45:17  rdx => 0xceb782308debf43c
0x555555555391   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555395   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xc40355a7098cae6a
11:45:17  0x80000000dd68 => 0xc40355a7098cae6a
0x555555555398   mov rax, qword ptr [rbp - 0x20]
11:45:17  rax => 0x80000000dd88
11:45:17  0x80000000dcb8 => 0x80000000dd88
0x55555555539c   mov rax, qword ptr [rax]
11:45:17  rax => 0xe18697b4cb6cd66f
11:45:17  0x80000000dd88 => 0xe18697b4cb6cd66f
0x55555555539f   xor rdx, rax
11:45:17  rdx => 0x2585c213c2e07805
11:45:17  rax => 0xe18697b4cb6cd66f
0x5555555553a2   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x5555555553a6   mov qword ptr [rax], rdx
11:45:17  0x80000000dd68 => 0x2585c213c2e07805
11:45:17  rdx => 0x2585c213c2e07805
0x5555555553a9   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x5555555553ad   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xfb66b363db848bc7
11:45:17  0x80000000dd80 => 0xfb66b363db848bc7
0x5555555553b0   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x5555555553b4   mov rax, qword ptr [rax]
11:45:17  rax => 0xceb782308debf43c
11:45:17  0x80000000dd78 => 0xceb782308debf43c
0x5555555553b7   xor rdx, rax
11:45:17  rdx => 0x35d13153566f7ffb
11:45:17  rax => 0xceb782308debf43c
0x5555555553ba   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x5555555553be   mov qword ptr [rax], rdx
11:45:17  0x80000000dd80 => 0x35d13153566f7ffb
11:45:17  rdx => 0x35d13153566f7ffb
0x5555555553c1   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x5555555553c5   mov rax, qword ptr [rax]
11:45:17  rax => 0xceb782308debf43c
11:45:17  0x80000000dd78 => 0xceb782308debf43c
0x5555555553c8   rol rax, 0x11
11:45:17  rax => 0x4611bd7e8799d6f
0x5555555553cc   mov rdx, rax
11:45:17  rdx => 0x4611bd7e8799d6f
11:45:17  rax => 0x4611bd7e8799d6f
0x5555555553cf   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x5555555553d3   mov qword ptr [rax], rdx
11:45:17  0x80000000dd78 => 0x4611bd7e8799d6f
11:45:17  rdx => 0x4611bd7e8799d6f
0x5555555553d6   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x5555555553da   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x35d13153566f7ffb
11:45:17  0x80000000dd80 => 0x35d13153566f7ffb
0x5555555553dd   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x5555555553e1   mov rax, qword ptr [rax]
11:45:17  rax => 0xa3d04cf5deeba7a9
11:45:17  0x80000000dd70 => 0xa3d04cf5deeba7a9
0x5555555553e4   add rdx, rax
11:45:17  rdx => 0xd9a17e49355b27a4
11:45:17  rax => 0xa3d04cf5deeba7a9
0x5555555553e7   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x5555555553eb   mov qword ptr [rax], rdx
11:45:17  0x80000000dd80 => 0xd9a17e49355b27a4
11:45:17  rdx => 0xd9a17e49355b27a4
0x5555555553ee   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x5555555553f2   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xa3d04cf5deeba7a9
11:45:17  0x80000000dd70 => 0xa3d04cf5deeba7a9
0x5555555553f5   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x5555555553f9   add rax, 0x28
11:45:17  rax => 0x80000000dd60
0x5555555553fd   mov rax, qword ptr [rax]
11:45:17  rax => 0x550cf76c3a481454
11:45:17  0x80000000dd60 => 0x550cf76c3a481454
0x555555555400   add rdx, rax
11:45:17  rdx => 0xf8dd44621933bbfd
11:45:17  rax => 0x550cf76c3a481454
0x555555555403   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x555555555407   mov qword ptr [rax], rdx
11:45:17  0x80000000dd70 => 0xf8dd44621933bbfd
11:45:17  rdx => 0xf8dd44621933bbfd
0x55555555540a   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x55555555540e   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x550cf76c3a481454
11:45:17  0x80000000dd60 => 0x550cf76c3a481454
0x555555555411   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0x80000000dd80
11:45:17  0x80000000dcb0 => 0x80000000dd80
0x555555555415   mov rax, qword ptr [rax]
11:45:17  rax => 0xd9a17e49355b27a4
11:45:17  0x80000000dd80 => 0xd9a17e49355b27a4
0x555555555418   xor rdx, rax
11:45:17  rdx => 0x8cad89250f1333f0
11:45:17  rax => 0xd9a17e49355b27a4
0x55555555541b   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x55555555541f   mov qword ptr [rax], rdx
11:45:17  0x80000000dd60 => 0x8cad89250f1333f0
11:45:17  rdx => 0x8cad89250f1333f0
0x555555555422   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x555555555426   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x4611bd7e8799d6f
11:45:17  0x80000000dd78 => 0x4611bd7e8799d6f
0x555555555429   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x55555555542d   mov rax, qword ptr [rax]
11:45:17  rax => 0xf8dd44621933bbfd
11:45:17  0x80000000dd70 => 0xf8dd44621933bbfd
0x555555555430   xor rdx, rax
11:45:17  rdx => 0xfcbc5fb5f14a2692
11:45:17  rax => 0xf8dd44621933bbfd
0x555555555433   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x555555555437   mov qword ptr [rax], rdx
11:45:17  0x80000000dd78 => 0xfcbc5fb5f14a2692
11:45:17  rdx => 0xfcbc5fb5f14a2692
0x55555555543a   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x55555555543e   mov rax, qword ptr [rax]
11:45:17  rax => 0xf8dd44621933bbfd
11:45:17  0x80000000dd70 => 0xf8dd44621933bbfd
0x555555555441   rol rax, 0x1c
11:45:17  rax => 0x21933bbfdf8dd446
0x555555555445   mov rdx, rax
11:45:17  rdx => 0x21933bbfdf8dd446
11:45:17  rax => 0x21933bbfdf8dd446
0x555555555448   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x55555555544c   mov qword ptr [rax], rdx
11:45:17  0x80000000dd70 => 0x21933bbfdf8dd446
11:45:17  rdx => 0x21933bbfdf8dd446
0x55555555544f   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x555555555453   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xfcbc5fb5f14a2692
11:45:17  0x80000000dd78 => 0xfcbc5fb5f14a2692
0x555555555456   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x55555555545a   mov rax, qword ptr [rax]
11:45:17  rax => 0x2585c213c2e07805
11:45:17  0x80000000dd68 => 0x2585c213c2e07805
0x55555555545d   add rdx, rax
11:45:17  rdx => 0x224221c9b42a9e97
11:45:17  rax => 0x2585c213c2e07805
0x555555555460   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x555555555464   mov qword ptr [rax], rdx
11:45:17  0x80000000dd78 => 0x224221c9b42a9e97
11:45:17  rdx => 0x224221c9b42a9e97
0x555555555467   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x55555555546b   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x2585c213c2e07805
11:45:17  0x80000000dd68 => 0x2585c213c2e07805
0x55555555546e   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x555555555472   add rax, 0x30
11:45:17  rax => 0x80000000dd68
0x555555555476   mov rax, qword ptr [rax]
11:45:17  rax => 0x2585c213c2e07805
11:45:17  0x80000000dd68 => 0x2585c213c2e07805
0x555555555479   add rdx, rax
11:45:17  rdx => 0x4b0b842785c0f00a
11:45:17  rax => 0x2585c213c2e07805
0x55555555547c   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555480   mov qword ptr [rax], rdx
11:45:17  0x80000000dd68 => 0x4b0b842785c0f00a
11:45:17  rdx => 0x4b0b842785c0f00a
0x555555555483   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555487   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xd3531faf7cfc29fa
11:45:17  0x80000000dd58 => 0xd3531faf7cfc29fa
0x55555555548a   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0x80000000dd78
11:45:17  0x80000000dca8 => 0x80000000dd78
0x55555555548e   mov rax, qword ptr [rax]
11:45:17  rax => 0x224221c9b42a9e97
11:45:17  0x80000000dd78 => 0x224221c9b42a9e97
0x555555555491   xor rdx, rax
11:45:17  rdx => 0xf1113e66c8d6b76d
11:45:17  rax => 0x224221c9b42a9e97
0x555555555494   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555498   mov qword ptr [rax], rdx
11:45:17  0x80000000dd58 => 0xf1113e66c8d6b76d
11:45:17  rdx => 0xf1113e66c8d6b76d
0x55555555549b   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x55555555549f   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x21933bbfdf8dd446
11:45:17  0x80000000dd70 => 0x21933bbfdf8dd446
0x5555555554a2   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x5555555554a6   mov rax, qword ptr [rax]
11:45:17  rax => 0x4b0b842785c0f00a
11:45:17  0x80000000dd68 => 0x4b0b842785c0f00a
0x5555555554a9   xor rdx, rax
11:45:17  rdx => 0x6a98bf985a4d244c
11:45:17  rax => 0x4b0b842785c0f00a
0x5555555554ac   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x5555555554b0   mov qword ptr [rax], rdx
11:45:17  0x80000000dd70 => 0x6a98bf985a4d244c
11:45:17  rdx => 0x6a98bf985a4d244c
0x5555555554b3   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x5555555554b7   mov rax, qword ptr [rax]
11:45:17  rax => 0x4b0b842785c0f00a
11:45:17  0x80000000dd68 => 0x4b0b842785c0f00a
0x5555555554ba   ror rax, 0x19
11:45:17  rax => 0xe078052585c213c2
0x5555555554be   mov rdx, rax
11:45:17  rdx => 0xe078052585c213c2
11:45:17  rax => 0xe078052585c213c2
0x5555555554c1   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x5555555554c5   mov qword ptr [rax], rdx
11:45:17  0x80000000dd68 => 0xe078052585c213c2
11:45:17  rdx => 0xe078052585c213c2
0x5555555554c8   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x5555555554cc   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x6a98bf985a4d244c
11:45:17  0x80000000dd70 => 0x6a98bf985a4d244c
0x5555555554cf   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555554d3   mov rax, qword ptr [rax]
11:45:17  rax => 0x8cad89250f1333f0
11:45:17  0x80000000dd60 => 0x8cad89250f1333f0
0x5555555554d6   add rdx, rax
11:45:17  rdx => 0xf74648bd6960583c
11:45:17  rax => 0x8cad89250f1333f0
0x5555555554d9   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x5555555554dd   mov qword ptr [rax], rdx
11:45:17  0x80000000dd70 => 0xf74648bd6960583c
11:45:17  rdx => 0xf74648bd6960583c
0x5555555554e0   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555554e4   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x8cad89250f1333f0
11:45:17  0x80000000dd60 => 0x8cad89250f1333f0
0x5555555554e7   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x5555555554eb   add rax, 0x38
11:45:17  rax => 0x80000000dd70
0x5555555554ef   mov rax, qword ptr [rax]
11:45:17  rax => 0xf74648bd6960583c
11:45:17  0x80000000dd70 => 0xf74648bd6960583c
0x5555555554f2   add rdx, rax
11:45:17  rdx => 0x83f3d1e278738c2c
11:45:17  rax => 0xf74648bd6960583c
0x5555555554f5   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555554f9   mov qword ptr [rax], rdx
11:45:17  0x80000000dd60 => 0x83f3d1e278738c2c
11:45:17  rdx => 0x83f3d1e278738c2c
0x5555555554fc   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555500   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xcd78e2294a4a921c
11:45:17  0x80000000dd50 => 0xcd78e2294a4a921c
0x555555555503   mov rax, qword ptr [rbp + 0x10]
11:45:17  rax => 0x80000000dd70
11:45:17  0x80000000dce8 => 0x80000000dd70
0x555555555507   mov rax, qword ptr [rax]
11:45:17  rax => 0xf74648bd6960583c
11:45:17  0x80000000dd70 => 0xf74648bd6960583c
0x55555555550a   xor rdx, rax
11:45:17  rdx => 0x3a3eaa94232aca20
11:45:17  rax => 0xf74648bd6960583c
0x55555555550d   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555511   mov qword ptr [rax], rdx
11:45:17  0x80000000dd50 => 0x3a3eaa94232aca20
11:45:17  rdx => 0x3a3eaa94232aca20
0x555555555514   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555518   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xe078052585c213c2
11:45:17  0x80000000dd68 => 0xe078052585c213c2
0x55555555551b   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x55555555551f   mov rax, qword ptr [rax]
11:45:17  rax => 0x83f3d1e278738c2c
11:45:17  0x80000000dd60 => 0x83f3d1e278738c2c
0x555555555522   xor rdx, rax
11:45:17  rdx => 0x638bd4c7fdb19fee
11:45:17  rax => 0x83f3d1e278738c2c
0x555555555525   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555529   mov qword ptr [rax], rdx
11:45:17  0x80000000dd68 => 0x638bd4c7fdb19fee
11:45:17  rdx => 0x638bd4c7fdb19fee
0x55555555552c   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x555555555530   mov rax, qword ptr [rax]
11:45:17  rax => 0x83f3d1e278738c2c
11:45:17  0x80000000dd60 => 0x83f3d1e278738c2c
0x555555555533   ror rax, 7
11:45:17  rax => 0x5907e7a3c4f0e718
0x555555555537   mov rdx, rax
11:45:17  rdx => 0x5907e7a3c4f0e718
11:45:17  rax => 0x5907e7a3c4f0e718
0x55555555553a   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x55555555553e   mov qword ptr [rax], rdx
11:45:17  0x80000000dd60 => 0x5907e7a3c4f0e718
11:45:17  rdx => 0x5907e7a3c4f0e718
0x555555555541   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555545   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x638bd4c7fdb19fee
11:45:17  0x80000000dd68 => 0x638bd4c7fdb19fee
0x555555555548   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x55555555554c   mov rax, qword ptr [rax]
11:45:17  rax => 0xf1113e66c8d6b76d
11:45:17  0x80000000dd58 => 0xf1113e66c8d6b76d
0x55555555554f   add rdx, rax
11:45:17  rdx => 0x549d132ec688575b
11:45:17  rax => 0xf1113e66c8d6b76d
0x555555555552   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555556   mov qword ptr [rax], rdx
11:45:17  0x80000000dd68 => 0x549d132ec688575b
11:45:17  rdx => 0x549d132ec688575b
0x555555555559   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x55555555555d   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xf1113e66c8d6b76d
11:45:17  0x80000000dd58 => 0xf1113e66c8d6b76d
0x555555555560   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x555555555564   add rax, 0x40
11:45:17  rax => 0x80000000dd78
0x555555555568   mov rax, qword ptr [rax]
11:45:17  rax => 0x224221c9b42a9e97
11:45:17  0x80000000dd78 => 0x224221c9b42a9e97
0x55555555556b   add rdx, rax
11:45:17  rdx => 0x135360307d015604
11:45:17  rax => 0x224221c9b42a9e97
0x55555555556e   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555572   mov qword ptr [rax], rdx
11:45:17  0x80000000dd58 => 0x135360307d015604
11:45:17  rdx => 0x135360307d015604
0x555555555575   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x555555555579   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xf9cf42e83f12e891
11:45:17  0x80000000dd48 => 0xf9cf42e83f12e891
0x55555555557c   mov rax, qword ptr [rbp + 0x18]
11:45:17  rax => 0x80000000dd68
11:45:17  0x80000000dcf0 => 0x80000000dd68
0x555555555580   mov rax, qword ptr [rax]
11:45:17  rax => 0x549d132ec688575b
11:45:17  0x80000000dd68 => 0x549d132ec688575b
0x555555555583   xor rdx, rax
11:45:17  rdx => 0xad5251c6f99abfca
11:45:17  rax => 0x549d132ec688575b
0x555555555586   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555558a   mov qword ptr [rax], rdx
11:45:17  0x80000000dd48 => 0xad5251c6f99abfca
11:45:17  rdx => 0xad5251c6f99abfca
0x55555555558d   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x555555555591   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x5907e7a3c4f0e718
11:45:17  0x80000000dd60 => 0x5907e7a3c4f0e718
0x555555555594   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555598   mov rax, qword ptr [rax]
11:45:17  rax => 0x135360307d015604
11:45:17  0x80000000dd58 => 0x135360307d015604
0x55555555559b   xor rdx, rax
11:45:17  rdx => 0x4a548793b9f1b11c
11:45:17  rax => 0x135360307d015604
0x55555555559e   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555555a2   mov qword ptr [rax], rdx
11:45:17  0x80000000dd60 => 0x4a548793b9f1b11c
11:45:17  rdx => 0x4a548793b9f1b11c
0x5555555555a5   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x5555555555a9   mov rax, qword ptr [rax]
11:45:17  rax => 0x135360307d015604
11:45:17  0x80000000dd58 => 0x135360307d015604
0x5555555555ac   ror rax, 9
11:45:17  rax => 0x209a9b0183e80ab
0x5555555555b0   mov rdx, rax
11:45:17  rdx => 0x209a9b0183e80ab
11:45:17  rax => 0x209a9b0183e80ab
0x5555555555b3   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x5555555555b7   mov qword ptr [rax], rdx
11:45:17  0x80000000dd58 => 0x209a9b0183e80ab
11:45:17  rdx => 0x209a9b0183e80ab
0x5555555555ba   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555555be   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x4a548793b9f1b11c
11:45:17  0x80000000dd60 => 0x4a548793b9f1b11c
0x5555555555c1   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x5555555555c5   mov rax, qword ptr [rax]
11:45:17  rax => 0x3a3eaa94232aca20
11:45:17  0x80000000dd50 => 0x3a3eaa94232aca20
0x5555555555c8   add rdx, rax
11:45:17  rdx => 0x84933227dd1c7b3c
11:45:17  rax => 0x3a3eaa94232aca20
0x5555555555cb   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555555cf   mov qword ptr [rax], rdx
11:45:17  0x80000000dd60 => 0x84933227dd1c7b3c
11:45:17  rdx => 0x84933227dd1c7b3c
0x5555555555d2   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x5555555555d6   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x3a3eaa94232aca20
11:45:17  0x80000000dd50 => 0x3a3eaa94232aca20
0x5555555555d9   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x5555555555dd   add rax, 0x48
11:45:17  rax => 0x80000000dd80
0x5555555555e1   mov rax, qword ptr [rax]
11:45:17  rax => 0xd9a17e49355b27a4
11:45:17  0x80000000dd80 => 0xd9a17e49355b27a4
0x5555555555e4   add rdx, rax
11:45:17  rdx => 0x13e028dd5885f1c4
11:45:17  rax => 0xd9a17e49355b27a4
0x5555555555e7   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x5555555555eb   mov qword ptr [rax], rdx
11:45:17  0x80000000dd50 => 0x13e028dd5885f1c4
11:45:17  rdx => 0x13e028dd5885f1c4
0x5555555555ee   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555555f2   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xb361a2fa85f32433
11:45:17  0x80000000dd40 => 0xb361a2fa85f32433
0x5555555555f5   mov rax, qword ptr [rbp + 0x20]
11:45:17  rax => 0x80000000dd60
11:45:17  0x80000000dcf8 => 0x80000000dd60
0x5555555555f9   mov rax, qword ptr [rax]
11:45:17  rax => 0x84933227dd1c7b3c
11:45:17  0x80000000dd60 => 0x84933227dd1c7b3c
0x5555555555fc   xor rdx, rax
11:45:17  rdx => 0x37f290dd58ef5f0f
11:45:17  rax => 0x84933227dd1c7b3c
0x5555555555ff   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x555555555603   mov qword ptr [rax], rdx
11:45:17  0x80000000dd40 => 0x37f290dd58ef5f0f
11:45:17  rdx => 0x37f290dd58ef5f0f
0x555555555606   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x55555555560a   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x209a9b0183e80ab
11:45:17  0x80000000dd58 => 0x209a9b0183e80ab
0x55555555560d   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555611   mov rax, qword ptr [rax]
11:45:17  rax => 0x13e028dd5885f1c4
11:45:17  0x80000000dd50 => 0x13e028dd5885f1c4
0x555555555614   xor rdx, rax
11:45:17  rdx => 0x11e9816d40bb716f
11:45:17  rax => 0x13e028dd5885f1c4
0x555555555617   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x55555555561b   mov qword ptr [rax], rdx
11:45:17  0x80000000dd58 => 0x11e9816d40bb716f
11:45:17  rdx => 0x11e9816d40bb716f
0x55555555561e   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555622   mov rax, qword ptr [rax]
11:45:17  rax => 0x13e028dd5885f1c4
11:45:17  0x80000000dd50 => 0x13e028dd5885f1c4
0x555555555625   ror rax, 0xa
11:45:17  rax => 0x7104f80a3756217c
0x555555555629   mov rdx, rax
11:45:17  rdx => 0x7104f80a3756217c
11:45:17  rax => 0x7104f80a3756217c
0x55555555562c   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555630   mov qword ptr [rax], rdx
11:45:17  0x80000000dd50 => 0x7104f80a3756217c
11:45:17  rdx => 0x7104f80a3756217c
0x555555555633   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555637   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x11e9816d40bb716f
11:45:17  0x80000000dd58 => 0x11e9816d40bb716f
0x55555555563a   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555563e   mov rax, qword ptr [rax]
11:45:17  rax => 0xad5251c6f99abfca
11:45:17  0x80000000dd48 => 0xad5251c6f99abfca
0x555555555641   add rdx, rax
11:45:17  rdx => 0xbf3bd3343a563139
11:45:17  rax => 0xad5251c6f99abfca
0x555555555644   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555648   mov qword ptr [rax], rdx
11:45:17  0x80000000dd58 => 0xbf3bd3343a563139
11:45:17  rdx => 0xbf3bd3343a563139
0x55555555564b   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555564f   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xad5251c6f99abfca
11:45:17  0x80000000dd48 => 0xad5251c6f99abfca
0x555555555652   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x555555555656   add rax, 0x50
11:45:17  rax => 0x80000000dd88
0x55555555565a   mov rax, qword ptr [rax]
11:45:17  rax => 0xe18697b4cb6cd66f
11:45:17  0x80000000dd88 => 0xe18697b4cb6cd66f
0x55555555565d   add rdx, rax
11:45:17  rdx => 0x8ed8e97bc5079639
11:45:17  rax => 0xe18697b4cb6cd66f
0x555555555660   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x555555555664   mov qword ptr [rax], rdx
11:45:17  0x80000000dd48 => 0x8ed8e97bc5079639
11:45:17  rdx => 0x8ed8e97bc5079639
0x555555555667   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x55555555566b   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xca55ef69b63cd406
11:45:17  0x80000000dd98 => 0xca55ef69b63cd406
0x55555555566e   mov rax, qword ptr [rbp + 0x28]
11:45:17  rax => 0x80000000dd58
11:45:17  0x80000000dd00 => 0x80000000dd58
0x555555555672   mov rax, qword ptr [rax]
11:45:17  rax => 0xbf3bd3343a563139
11:45:17  0x80000000dd58 => 0xbf3bd3343a563139
0x555555555675   xor rdx, rax
11:45:17  rdx => 0x756e3c5d8c6ae53f
11:45:17  rax => 0xbf3bd3343a563139
0x555555555678   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x55555555567c   mov qword ptr [rax], rdx
11:45:17  0x80000000dd98 => 0x756e3c5d8c6ae53f
11:45:17  rdx => 0x756e3c5d8c6ae53f
0x55555555567f   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555683   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x7104f80a3756217c
11:45:17  0x80000000dd50 => 0x7104f80a3756217c
0x555555555686   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555568a   mov rax, qword ptr [rax]
11:45:17  rax => 0x8ed8e97bc5079639
11:45:17  0x80000000dd48 => 0x8ed8e97bc5079639
0x55555555568d   xor rdx, rax
11:45:17  rdx => 0xffdc1171f251b745
11:45:17  rax => 0x8ed8e97bc5079639
0x555555555690   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x555555555694   mov qword ptr [rax], rdx
11:45:17  0x80000000dd50 => 0xffdc1171f251b745
11:45:17  rdx => 0xffdc1171f251b745
0x555555555697   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555569b   mov rax, qword ptr [rax]
11:45:17  rax => 0x8ed8e97bc5079639
11:45:17  0x80000000dd48 => 0x8ed8e97bc5079639
0x55555555569e   rol rax, 0x16
11:45:17  rax => 0x5ef141e58e63b63a
0x5555555556a2   mov rdx, rax
11:45:17  rdx => 0x5ef141e58e63b63a
11:45:17  rax => 0x5ef141e58e63b63a
0x5555555556a5   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x5555555556a9   mov qword ptr [rax], rdx
11:45:17  0x80000000dd48 => 0x5ef141e58e63b63a
11:45:17  rdx => 0x5ef141e58e63b63a
0x5555555556ac   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x5555555556b0   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xffdc1171f251b745
11:45:17  0x80000000dd50 => 0xffdc1171f251b745
0x5555555556b3   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555556b7   mov rax, qword ptr [rax]
11:45:17  rax => 0x37f290dd58ef5f0f
11:45:17  0x80000000dd40 => 0x37f290dd58ef5f0f
0x5555555556ba   add rdx, rax
11:45:17  rdx => 0x37cea24f4b411654
11:45:17  rax => 0x37f290dd58ef5f0f
0x5555555556bd   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x5555555556c1   mov qword ptr [rax], rdx
11:45:17  0x80000000dd50 => 0x37cea24f4b411654
11:45:17  rdx => 0x37cea24f4b411654
0x5555555556c4   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555556c8   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x37f290dd58ef5f0f
11:45:17  0x80000000dd40 => 0x37f290dd58ef5f0f
0x5555555556cb   mov rax, qword ptr [rbp - 8]
11:45:17  rax => 0x80000000dd38
11:45:17  0x80000000dcd0 => 0x80000000dd38
0x5555555556cf   add rax, 0x58
11:45:17  rax => 0x80000000dd90
0x5555555556d3   mov rax, qword ptr [rax]
11:45:17  rax => 0xe3dfe4107ce518b4
11:45:17  0x80000000dd90 => 0xe3dfe4107ce518b4
0x5555555556d6   add rdx, rax
11:45:17  rdx => 0x1bd274edd5d477c3
11:45:17  rax => 0xe3dfe4107ce518b4
0x5555555556d9   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x5555555556dd   mov qword ptr [rax], rdx
11:45:17  0x80000000dd40 => 0x1bd274edd5d477c3
11:45:17  rdx => 0x1bd274edd5d477c3
0x5555555556e0   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555556e4   mov rdx, qword ptr [rax]
11:45:17  rdx => 0xe3dfe4107ce518b4
11:45:17  0x80000000dd90 => 0xe3dfe4107ce518b4
0x5555555556e7   mov rax, qword ptr [rbp + 0x30]
11:45:17  rax => 0x80000000dd50
11:45:17  0x80000000dd08 => 0x80000000dd50
0x5555555556eb   mov rax, qword ptr [rax]
11:45:17  rax => 0x37cea24f4b411654
11:45:17  0x80000000dd50 => 0x37cea24f4b411654
0x5555555556ee   xor rdx, rax
11:45:17  rdx => 0xd411465f37a40ee0
11:45:17  rax => 0x37cea24f4b411654
0x5555555556f1   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x80000000dd90
11:45:17  0x80000000dcc0 => 0x80000000dd90
0x5555555556f5   mov qword ptr [rax], rdx
11:45:17  0x80000000dd90 => 0xd411465f37a40ee0
11:45:17  rdx => 0xd411465f37a40ee0
0x5555555556f8   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x5555555556fc   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x5ef141e58e63b63a
11:45:17  0x80000000dd48 => 0x5ef141e58e63b63a
0x5555555556ff   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x555555555703   mov rax, qword ptr [rax]
11:45:17  rax => 0x1bd274edd5d477c3
11:45:17  0x80000000dd40 => 0x1bd274edd5d477c3
0x555555555706   xor rdx, rax
11:45:17  rdx => 0x452335085bb7c1f9
11:45:17  rax => 0x1bd274edd5d477c3
0x555555555709   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555570d   mov qword ptr [rax], rdx
11:45:17  0x80000000dd48 => 0x452335085bb7c1f9
11:45:17  rdx => 0x452335085bb7c1f9
0x555555555710   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x555555555714   mov rax, qword ptr [rax]
11:45:17  rax => 0x1bd274edd5d477c3
11:45:17  0x80000000dd40 => 0x1bd274edd5d477c3
0x555555555717   ror rax, 0x12
11:45:17  rax => 0x1df0c6f49d3b7575
0x55555555571b   mov rdx, rax
11:45:17  rdx => 0x1df0c6f49d3b7575
11:45:17  rax => 0x1df0c6f49d3b7575
0x55555555571e   mov rax, qword ptr [rbp + 0x40]
11:45:17  rax => 0x80000000dd40
11:45:17  0x80000000dd18 => 0x80000000dd40
0x555555555722   mov qword ptr [rax], rdx
11:45:17  0x80000000dd40 => 0x1df0c6f49d3b7575
11:45:17  rdx => 0x1df0c6f49d3b7575
0x555555555725   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x555555555729   mov rdx, qword ptr [rax]
11:45:17  rdx => 0x452335085bb7c1f9
11:45:17  0x80000000dd48 => 0x452335085bb7c1f9
0x55555555572c   mov rax, qword ptr [rbp - 0x10]
11:45:17  rax => 0x80000000dd98
11:45:17  0x80000000dcc8 => 0x80000000dd98
0x555555555730   mov rax, qword ptr [rax]
11:45:17  rax => 0x756e3c5d8c6ae53f
11:45:17  0x80000000dd98 => 0x756e3c5d8c6ae53f
0x555555555733   add rdx, rax
11:45:17  rdx => 0xba917165e822a738
11:45:17  rax => 0x756e3c5d8c6ae53f
0x555555555736   mov rax, qword ptr [rbp + 0x38]
11:45:17  rax => 0x80000000dd48
11:45:17  0x80000000dd10 => 0x80000000dd48
0x55555555573a   mov qword ptr [rax], rdx
11:45:17  0x80000000dd48 => 0xba917165e822a738
11:45:17  rdx => 0xba917165e822a738
0x55555555573d   nop 
0x55555555573e   pop rbp
11:45:17  rbp => 0x80000000ddb8
0x55555555573f   ret 
0x5555555558b6   add rsp, 0x40
11:45:17  rsp => 0x80000000dd28
0x5555555558ba   add qword ptr [rbp - 8], 1
11:45:17  0x80000000ddb0 => 0x2
0x5555555558bf   mov rax, qword ptr [rbp - 0x18]
11:45:17  rax => 0x14
11:45:17  0x80000000dda0 => 0x14
0x5555555558c3   shr rax, 3
11:45:17  rax => 0x2
0x5555555558c7   cmp qword ptr [rbp - 8], rax
11:45:17  0x80000000ddb0 => 0x2
11:45:17  rax => 0x2
0x5555555558cb   jb 0x55555555581a
0x5555555558d1   mov rdx, qword ptr [rbp - 0x20]
11:45:17  rdx => 0x756e3c5d8c6ae53f
11:45:17  0x80000000dd98 => 0x756e3c5d8c6ae53f
0x5555555558d5   mov rax, qword ptr [rbp - 0x28]
11:45:17  rax => 0xd411465f37a40ee0
11:45:17  0x80000000dd90 => 0xd411465f37a40ee0
0x5555555558d9   add rdx, rax
11:45:17  rdx => 0x497f82bcc40ef41f
11:45:17  rax => 0xd411465f37a40ee0
0x5555555558dc   mov rax, qword ptr [rbp - 0x30]
11:45:17  rax => 0xe18697b4cb6cd66f
11:45:17  0x80000000dd88 => 0xe18697b4cb6cd66f
0x5555555558e0   add rdx, rax
11:45:17  rdx => 0x2b061a718f7bca8e
11:45:17  rax => 0xe18697b4cb6cd66f
0x5555555558e3   mov rax, qword ptr [rbp - 0x38]
11:45:17  rax => 0xd9a17e49355b27a4
11:45:17  0x80000000dd80 => 0xd9a17e49355b27a4
0x5555555558e7   add rdx, rax
11:45:17  rdx => 0x4a798bac4d6f232
11:45:17  rax => 0xd9a17e49355b27a4
0x5555555558ea   mov rax, qword ptr [rbp - 0x40]
11:45:17  rax => 0x224221c9b42a9e97
11:45:17  0x80000000dd78 => 0x224221c9b42a9e97
0x5555555558ee   add rdx, rax
11:45:17  rdx => 0x26e9ba84790190c9
11:45:17  rax => 0x224221c9b42a9e97
0x5555555558f1   mov rax, qword ptr [rbp - 0x48]
11:45:17  rax => 0xf74648bd6960583c
11:45:17  0x80000000dd70 => 0xf74648bd6960583c
0x5555555558f5   add rdx, rax
11:45:17  rdx => 0x1e300341e261e905
11:45:17  rax => 0xf74648bd6960583c
0x5555555558f8   mov rax, qword ptr [rbp - 0x50]
11:45:17  rax => 0x549d132ec688575b
11:45:17  0x80000000dd68 => 0x549d132ec688575b
0x5555555558fc   add rdx, rax
11:45:17  rdx => 0x72cd1670a8ea4060
11:45:17  rax => 0x549d132ec688575b
0x5555555558ff   mov rax, qword ptr [rbp - 0x58]
11:45:17  rax => 0x84933227dd1c7b3c
11:45:17  0x80000000dd60 => 0x84933227dd1c7b3c
0x555555555903   add rdx, rax
11:45:17  rdx => 0xf76048988606bb9c
11:45:17  rax => 0x84933227dd1c7b3c
0x555555555906   mov rax, qword ptr [rbp - 0x60]
11:45:17  rax => 0xbf3bd3343a563139
11:45:17  0x80000000dd58 => 0xbf3bd3343a563139
0x55555555590a   add rdx, rax
11:45:17  rdx => 0xb69c1bccc05cecd5
11:45:17  rax => 0xbf3bd3343a563139
0x55555555590d   mov rax, qword ptr [rbp - 0x68]
11:45:17  rax => 0x37cea24f4b411654
11:45:17  0x80000000dd50 => 0x37cea24f4b411654
0x555555555911   add rdx, rax
11:45:17  rdx => 0xee6abe1c0b9e0329
11:45:17  rax => 0x37cea24f4b411654
0x555555555914   mov rax, qword ptr [rbp - 0x70]
11:45:17  rax => 0xba917165e822a738
11:45:17  0x80000000dd48 => 0xba917165e822a738
0x555555555918   add rdx, rax
11:45:17  rdx => 0xa8fc2f81f3c0aa61
11:45:17  rax => 0xba917165e822a738
0x55555555591b   mov rax, qword ptr [rbp - 0x78]
11:45:17  rax => 0x1df0c6f49d3b7575
11:45:17  0x80000000dd40 => 0x1df0c6f49d3b7575
0x55555555591f   add rax, rdx
11:45:17  rax => 0xc6ecf67690fc1fd6
11:45:17  rdx => 0xa8fc2f81f3c0aa61
0x555555555922   leave 
0x555555555923   ret 
0x555555555940   mov qword ptr [rbp - 8], rax
11:45:17  0x80000000ddf0 => 0xc6ecf67690fc1fd6
11:45:17  rax => 0xc6ecf67690fc1fd6
0x555555555944   mov rax, qword ptr [rbp - 0x30]
11:45:17  Symbolic memory found in 0x80000000ddc8 => num
11:45:17  Loading a value from a previous symbolic memory write num
11:45:17  Symbolic instruction mov executed, result: num
11:45:17  rax => 0x22b8
11:45:17  0x80000000ddc8 => 0x22b8
0x555555555948   rol rax, 0x20
11:45:17  Symbolic register found in rax => num
11:45:17  Symbolic instruction rol executed, result: (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff
11:45:17  rax => 0x22b800000000
0x55555555594c   mov qword ptr [rbp - 0x10], rax
11:45:17  Symbolic register found in rax => (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff
11:45:17  Instantiating v_op1 RealValue
11:45:17  Symbolic instruction mov executed, result: (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff
11:45:17  0x80000000dde8 => 0x22b800000000
11:45:17  rax => 0x22b800000000
0x555555555950   mov rax, qword ptr [rbp - 0x10]
11:45:17  Symbolic register found in rax => (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff
11:45:17  Loading a value from a previous symbolic memory write (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff
11:45:17  Symbolic instruction mov executed, result: (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff
11:45:17  rax => 0x22b800000000
11:45:17  0x80000000dde8 => 0x22b800000000
0x555555555954   mov edx, eax
11:45:17  Symbolic register found in eax => (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff
11:45:17  Symbolic instruction mov executed, result: (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff & 0xffffffff
11:45:17  edx => 0x0
11:45:17  eax => 0x0
0x555555555956   mov rax, qword ptr [rbp - 0x10]
11:45:17  Symbolic register found in rax => (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff
11:45:17  Loading a value from a previous symbolic memory write (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff
11:45:17  Symbolic instruction mov executed, result: (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff
11:45:17  rax => 0x22b800000000
11:45:17  0x80000000dde8 => 0x22b800000000
0x55555555595a   shr rax, 0x20
11:45:17  Symbolic register found in rax => (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff
11:45:17  Symbolic instruction shr executed, result: ((num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff)>>0x20 & 0xffffffffffffffff
11:45:17  rax => 0x22b8
0x55555555595e   xor rax, rdx
11:45:17  Symbolic register found in rax => ((num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff)>>0x20 & 0xffffffffffffffff
11:45:17  Creating new varname var_00001 for rax=>((num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff)>>0x20 & 0xffffffffffffffff
11:45:17  Symbolic instruction xor executed, result: var_00001 ^ (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff & 0xffffffff
11:45:17  rax => 0x22b8
11:45:17  rdx => 0x0
0x555555555961   xor qword ptr [rbp - 8], rax
11:45:17  Symbolic register found in rax => var_00001 ^ (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff & 0xffffffff
11:45:17  Creating new varname var_00002 for rax=>var_00001 ^ (num<<0x20 | num>>0xffffffffffffffe8) & 0xffffffffffffffff & 0xffffffff
11:45:17  Instantiating v_op1 RealValue
11:45:17  Symbolic instruction xor executed, result: 0xc6ecf67690fc1fd6 ^ var_00002
11:45:17  0x80000000ddf0 => 0xc6ecf67690fc3d6e
11:45:17  rax => 0x22b8
0x555555555965   movabs rax, 0x123456789abcdef
11:45:17  Symbolic register found in rax => var_00002
11:45:17  Symbolic operation gives no result
11:45:17  rax = 0x22b8 
11:45:17  rax => 0x123456789abcdef
0x55555555596f   mov qword ptr [rbp - 0x18], rax
11:45:17  0x80000000dde0 => 0x123456789abcdef
11:45:17  rax => 0x123456789abcdef
0x555555555973   mov rax, qword ptr [rbp - 0x30]
11:45:17  Symbolic memory found in 0x80000000ddc8 => num
11:45:17  Loading a value from a previous symbolic memory write num
11:45:17  Symbolic instruction mov executed, result: num
11:45:17  rax => 0x22b8
11:45:17  0x80000000ddc8 => 0x22b8
0x555555555977   xor qword ptr [rbp - 0x18], rax
11:45:17  Symbolic register found in rax => num
11:45:17  Instantiating v_op1 RealValue
11:45:17  Symbolic instruction xor executed, result: 0x123456789abcdef ^ num
11:45:17  0x80000000dde0 => 0x123456789abef57
11:45:17  rax => 0x22b8
0x55555555597b   mov rax, qword ptr [rbp - 0x30]
11:45:17  Symbolic register found in rax => num
11:45:17  Loading a value from a previous symbolic memory write num
11:45:17  Symbolic instruction mov executed, result: num
11:45:17  rax => 0x22b8
11:45:17  0x80000000ddc8 => 0x22b8
0x55555555597f   rol rax, 0x10
11:45:17  Symbolic register found in rax => num
11:45:17  Symbolic instruction rol executed, result: (num<<0x10 | num>>0xfffffffffffffff8) & 0xffffffffffffffff
11:45:17  rax => 0x22b80000
0x555555555983   xor qword ptr [rbp - 0x18], rax
11:45:17  Symbolic memory found in 0x80000000dde0 => 0x123456789abcdef ^ num
11:45:17  Loading a value from a previous symbolic memory write 0x123456789abcdef ^ num
11:45:17  Symbolic instruction xor executed, result: 0x123456789abcdef ^ num ^ (num<<0x10 | num>>0xfffffffffffffff8) & 0xffffffffffffffff
11:45:17  0x80000000dde0 => 0x1234567ab13ef57
11:45:17  rax => 0x22b80000
0x555555555987   mov rax, qword ptr [rbp - 8]
11:45:17  Symbolic register found in rax => (num<<0x10 | num>>0xfffffffffffffff8) & 0xffffffffffffffff
11:45:17  Creating new varname var_00003 for mem_0x80000000dde0=>0x123456789abcdef ^ num ^ (num<<0x10 | num>>0xfffffffffffffff8) & 0xffffffffffffffff
11:45:17  Loading a value from a previous symbolic memory write 0xc6ecf67690fc1fd6 ^ var_00002
11:45:17  Symbolic instruction mov executed, result: 0xc6ecf67690fc1fd6 ^ var_00002
11:45:17  rax => 0xc6ecf67690fc3d6e
11:45:17  0x80000000ddf0 => 0xc6ecf67690fc3d6e
0x55555555598b   cmp rax, qword ptr [rbp - 0x18]
11:45:17  Symbolic register found in rax => 0xc6ecf67690fc1fd6 ^ var_00002
11:45:17  rax = 0xc6ecf67690fc3d6e 
11:45:17  0x80000000dde0 = 0x1234567ab13ef57
``