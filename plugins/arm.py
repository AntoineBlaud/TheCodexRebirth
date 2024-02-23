from tenet.taint_engine.values_container import SymRegister


def create_sym_register_factory():
    """
    CREATE A DICTIONARY OF SYMBOLIC REGISTERS AND THEIR PARTS.
    USED ALSO TO LINK A REGISTER PART TO ITS PARENT REGISTER.
    """
    registers = {}
    
    # x0-x31 registers for aaarch64
    for i in range(32):
        registers[f"x{i}"] = SymRegister(f"x{i}", 63, 0)
        
    # w0-w31 registers for aaarch64 and arm
    for i in range(32):
        registers[f"w{i}"] = SymRegister(f"w{i}", 15, 0, registers[f"x{i}"])
       
    # b0-b31 registers for aaarch64 and arm
    for i in range(32):
        registers[f"b{i}"] = SymRegister(f"b{i}", 7, 0, registers[f"w{i}"])
        
    # r0-r15 registers for arm
    for i in range(16):
        registers[f"r{i}"] = SymRegister(f"r{i}", 32, 0)
        
    
    SYM_REGISTER_FACTORY = {}
    
    # create the factory for aaarch64
    for i in range(32):
        SYM_REGISTER_FACTORY[f"x{i}"] = [registers[f"x{i}"], registers[f"w{i}"], registers[f"b{i}"]]
        SYM_REGISTER_FACTORY[f"w{i}"] = [registers[f"w{i}"], registers[f"b{i}"]]
        SYM_REGISTER_FACTORY[f"b{i}"] = [registers[f"b{i}"]]
        
    # create the factory for arm
    for i in range(16):
        SYM_REGISTER_FACTORY[f"r{i}"] = [registers[f"r{i}"],  registers[f"w{i}"], registers[f"b{i}"]] 
        
    return SYM_REGISTER_FACTORY



