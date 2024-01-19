import argparse
import re

def get_pc_reg(arch):
    if arch == "x86_64":
        return "RIP"
    elif arch == "x86":
        return "EIP"
    elif arch == "arm":
        return "R15"
    elif arch == "aarch64":
        return "PC"
    else:
        raise Exception("Unsupported architecture")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Input file")
    args = parser.parse_args()
    
    file = args.input
    filename = file.split("/")[-1]

    with open(args.input, "r") as f:
        data = f.read()
    arch = None
    if "RAX" in data:
        arch = "x86_64"
    elif "EAX" in data:
        arch = "x86"
    elif "R0" in data:
        arch = "arm"
    elif "x0" in data:
        arch = "aarch64"
        
    with open(f"{filename}.tenet", "w") as f:
        pc_reg = get_pc_reg(arch).lower()
        prev_addr = None
        first_line = True
        for line in data.split("\n"):
            conv_line = ["slide=0x0"]
            addr = line.split("\t")[1]
            # check addr is int16
            try:
                int(addr, 16)
                if int(addr, 16) < 0x1000:
                    addr = prev_addr
            except:
                addr = prev_addr
            if addr is None or first_line:
                first_line = False
                continue
            prev_addr = addr
            conv_line.append(f"{pc_reg}=0x{addr}")
            reg_vals = re.findall(r"([A-Z0-9]+)=([A-F0-9]+)", line)
            for reg, val in reg_vals:
                conv_line.append(f"{reg.lower()}=0x{val}")
            f.write(",".join(conv_line) + "\n")
            
main()