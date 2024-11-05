# Experimental Block Tracing for First-Seen Instructions

This project implements an experimental tracer that focuses on tracking blocks of code as they are first encountered. A key feature of this tracer is its ability to explore blocks even in the presence of pure dynamically resolved jumps, such as `jmp rax`. The tracer injects shellcode into the program, which compares the current execution target with previously seen targets, and triggers a breakpoint when a new target is detected.

### Key Features:
- **Tracing of dynamic jumps**: The tracer is capable of accurately following execution paths involving decoded jumps, which makes it particularly useful for tracing complex code paths in packers like Themida.


### **Limitations of Hooking in Native Code**

In this example, we have a block of native code:

```
Native block:
00000001490589C3     add     r11, 132h
00000001490589CA     add     [r11], r14
00000001490589CD     jmp     r15
00000001490589D0     push    7BEDF190h
```

After applying a hook or patch, it looks like this:

```
After patch:
00000001490589C3     add     r11, 132h
00000001490589CA     jmp     loc_14B691200  ; Jump to hooked code
00000001490589CF     nop                    ; Padding to preserve 5-byte hook size rounded to the next instruction size
00000001490589D0     push    7BEDF190h
```

### **The Problem:**

Normally, execution flows through the patched block without issue. However, if another part of the code **jumps directly to an instruction that has been partially overwritten**, it results in instruction corruption. 

In this case, there's another jump that targets `jmp r15` (the instruction that was at `0x00000001490589CD`):

```
00000001490589BB     jmp     loc_1490589CD  ; A direct jump targeting the original code at 0x1490589CD
```

But after the patch, the instruction layout has changed:

```
00000001490589CA     jmp     loc_14B691200  ; Hook inserted here
00000001490589CD     movsxd  eax, dword ptr [rdx]  ; Instruction corruption
```

Now, when the jump at `0x1490589BB` tries to land on the `jmp r15` instruction (which was at `0x1490589CD`), it instead lands **in the middle of a completely different instruction**, resulting in undefined behavior and **instruction corruption**. In this case, the code now interprets the bytes starting at `0x1490589CD` as a `movsxd` instruction, which leads to a crash or other unintended behavior.

### **Explanation of the Issue:**

- The original `jmp r15` instruction was only 2 bytes long, but the hook you applied is 5 bytes. To fit the hook, several instructions were modified or replaced.
- However, a separate part of the code has a **hardcoded jump** directly to the `jmp r15` instruction, which was part of the original block at `0x1490589CD`.
- After applying the patch, this jump now lands in the middle of an instruction, corrupting the flow of execution. Since the `jmp` lands between two instructions (where the original instruction used to be), the CPU decodes the wrong set of instructions, leading to **corruption and a crash**.


### Solution ? 

Relocate each block so they are executed first, creating space to modify the jump targets