from tenet.taint_engine.values_container import SymRegister

def create_sym_register_factory():
    """
    CREATE A DICTIONARY OF SYMBOLIC REGISTERS AND THEIR PARTS.
    USED ALSO TO LINK A REGISTER PART TO ITS PARENT REGISTER.
    """
    registers = {}
    
    # x0-x31 registers for aaarch64
    for i in range(32):
        registers[f"X{i}"] = SymRegister(f"X{i}", 63, 0)
        
        
    # r0-r15 registers for arm
    for i in range(16):
        registers[f"R{i}"] = SymRegister(f"R{i}", 32, 0)
        
    
    SYM_REGISTER_FACTORY = {}
    
    # create the factory for aaarch64
    for i in range(32):
        SYM_REGISTER_FACTORY[f"X{i}"] = [registers[f"X{i}"]]
        
    # create the factory for arm
    for i in range(16):
        SYM_REGISTER_FACTORY[f"R{i}"] = [registers[f"R{i}"]] 
        
    return SYM_REGISTER_FACTORY



def get_parent_register(register_name, arch_size):
    register_name = register_name.upper()
    
    return register_name
    
        
