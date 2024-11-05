from unicorn import *
from unicorn.x86_const import *
import time


X86_CODE32_LOOP = b"\x49\x75\xFD\xB8\x01\x00\x00\x00\x31\xDB\x00\x00\x00\x00"  # DEC ecx; JNZ -4 (jump to self-loop until ECX == 0)

# memory address where emulation starts
ADDRESS = 0x1000000


def test_i386_loop(count):
    print("Emulate i386 code that loop")
    try:
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32_LOOP)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_ECX, 0x100000000)
        mu.reg_write(UC_X86_REG_EDX, 0x7890000000)

        start = time.time()
        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32_LOOP), timeout=1000*UC_SECOND_SCALE, count=count)
        end = time.time()
        ips = int(count / (end - start))

        print(f">>> Emulation done. Below is the CPU context. Instructions per second (IPS) : {ips:,}")

        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        print(">>> ECX = 0x%x" %r_ecx)
        print(">>> EDX = 0x%x" %r_edx)

    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == '__main__':
    test_i386_loop(100000000)