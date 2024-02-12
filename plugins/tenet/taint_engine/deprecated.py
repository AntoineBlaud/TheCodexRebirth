class QilingRunner(Runner):
    def __init__(self, engine, arch, debug_level, timeout, symbolic_check, *args):
        super().__init__(engine, arch, debug_level, timeout, symbolic_check, *args)

        self.ql = engine.ql

        # Check if the architecture is 32-bit or 64-bit
        if self.ql.arch.type == QL_ARCH.X8664:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

        elif self.ql.arch.type == QL_ARCH.X86:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
            
        elif self.ql.arch.type == QL_ARCH.ARM:
            self.cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            self.ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        
        elif self.ql.arch.type == QL_ARCH.ARM64:
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            self.ks = Ks(KS_ARCH_ARM64, KS_MODE_ARM)

        # Find the base and end address of the text section
        self.text_base = self.ql.loader.images[0].base
        self.text_end = self.ql.loader.images[0].end

    def initialize_configuration(self):
        """
        Initialize the global shared among all the modules via superglobal library
        """

        if self.ql.arch.type in (QL_ARCH.X86, QL_ARCH.X8664):
            self.CONFIG["BAD_OPERANDS"] = BAD_OPERANDS_X86_64

        if self.ql.arch.type in (QL_ARCH.X8664, QL_ARCH.ARM64):
            self.CONFIG["BINARY_MAX_MASK"] = 0xFFFFFFFFFFFFFFFF
            self.CONFIG["BINARY_ARCH_SIZE"] = 64

        elif self.ql.arch.type in (QL_ARCH.X86, QL_ARCH.ARM):
            self.CONFIG["BINARY_MAX_MASK"] = 0xFFFFFFFF
            self.CONFIG["BINARY_ARCH_SIZE"] = 32
            
        
        self.CONFIG["PC_REG_NAME"] = self.ql.arch.regs.arch_pc
        self.CONFIG["SP_REG_NAME"] = self.ql.arch.regs.arch_sp
    
        # make first update
        setglobal("CONFIG", self.CONFIG)
        # Must be called after CONFIG BINARY_MAX_MASK and BINARY_ARCH_SIZE are set
        self.CONFIG["SYM_REGISTER_FACTORY"] = create_sym_register_factory()
        self.CONFIG["IS_INITIALIZED"] = True
        # make second update
        setglobal("CONFIG", self.CONFIG)

    def initialize(self):
        if self.CONFIG["IS_INITIALIZED"]:
            return
        # Synchronize config with the global config
        self.initialize_configuration()
        self.operation_engine.set_config(self.CONFIG)
        super().initialize()

        # Set up memory read, memory write, and code hooks
        self.ql.hook_mem_read(self.memory_read_hook)
        self.ql.hook_mem_write(self.memory_write_hook)
        self.ql.hook_code(self.code_execution_hook)
        
    def memory_write_hook(self, ql: Qiling, access: int, address: int, size: int, value: int):
        assert access == UC_MEM_WRITE
        self.register_operations(self.operation_engine.evaluate_instruction(address, self.symbolic_taint_store))

    def memory_read_hook(self, ql: Qiling, access: int, address: int, size: int, value: int):
        assert access == UC_MEM_READ
        self.register_operations(self.operation_engine.evaluate_instruction(address, self.symbolic_taint_store))

    def code_execution_hook(self, ql: Qiling, address: int, size):
        try:
            if time.time() - self.start_time > self.timeout:
                raise UserStoppedExecution(f"Reached timeout of {self.timeout} seconds")

            # Get the current instruction and its address
            cinsn, cinsn_addr = (
                self.engine.get_currrent_instruction_disass(),
                self.engine.get_ea(),
            )
            # Check if we have reached the user-defined end address for emulation
            if cinsn_addr in self.addr_emu_end:
                raise UserStoppedExecution("Reached user-defined end address")

            # If the instruction involves memory access, delegate to dedicated functions (mem_read, mem_write)
            if check_memory_access(cinsn):
                return

            # Evaluate the instruction with the current codex state
            operation = self.operation_engine.evaluate_instruction(None, self.symbolic_taint_store)
            self.register_operations(operation)
        finally:
            pass

    def run_emulation(self):
        # must be call at the start of the emulation and not before
        self.initialize()
        # Start measuring emulation time
        self.start_time = time.time()
        try:
            # Start Qiling engine emulation
            self.ql.run(self.addr_emu_start)
        except (UserStoppedExecution, unicorn.UcError) as e:
            logger.error("Emulation stopped: %s", e)
        finally:
            # Calculate emulation time and instructions per second
            end_time = time.time()
            self.emulation_time += end_time - self.start_time
            instructions_per_second = self.operation_executed_count.value / self.emulation_time
            # Format the output message
            output = "\n".join(
                [
                    "=" * 80,
                    f"Emulation time: {self.emulation_time:.1f} seconds",
                    f"{self.operation_executed_count.value} instructions executed",
                    f"Operations per second: {instructions_per_second:.1f}",
                    "=" * 80,
                ]
            )
            # Log emulation results
            logger.info(output)

            # print performance report
            global profile
            profile.print_stats()
            
            
            
   self.is_initialized = False
        print("Initializing CodexRebirth context (can take up to 180 seconds, please be patient)...")
        # Initialize the backend for emulation.
        self.initialize_symbolic_engine(config)
        self.is_initialized = True

    def run_emulation_thread(self, callback, main_thread):
        self.sym_runner.run_emulation()
        # fetch the main thread
        # call the callback function with the main thread
        ida_kernwin.execute_sync(callback, ida_kernwin.MFF_FAST)

    def run_emulation(self, callback):
        # Check if the debugger is active; otherwise, there's no need to map segments.
        if not ida_dbg.is_debugger_on():
            show_msgbox("Please start the debugger before running the emulation")
            return
        # Map IDA Pro segments to Qiling.
        self.map_segments_to_engine()
        # Set up the emulation environment.
        self.map_registers()
        # Run the emulation in a separate thread.
        main_thread = idaapi.get_current_thread()
        Thread(
            target=self.run_emulation_thread,
            args=(
                callback,
                main_thread,
            ),
        ).start()

    def setup_logger(self):
        return tempfile.NamedTemporaryFile(prefix="cr_trace", suffix=".txt", delete=False, mode="w")

    def get_binary_path(self):
        """
        Get the path to the binary file from IDA Pro.

        Returns:
            str: Path to the binary file.
        """
        return os.path.join(os.getcwd(), idaapi.get_input_file_path())

    def initialize_symbolic_engine(self, config):
        """
        Initialize the backend for emulation:

        1. Redirect standard output and standard error to the log file.
        2. Redirect standard input to /dev/null to suppress user input.
        3. Configure Qiling with the provided binary and rootfs paths.
        4. Set up the emulation environment.
        """

        # Extract configuration parameters.
        binary_path = self.get_binary_path()
        binary_name = os.path.basename(binary_path)
        rootfs_path = config["rootfs_path"]
        log_plain = config["log_plain"]
        debug_level = config["debug_level"]
        timeout = config["timeout"]
        symbolic_check = config["symbolic_check"]
        info = idaapi.get_inf_structure()

        if info.is_64bit():
            self.arch = ArchAMD64()
            self.ql_arch = QL_ARCH.X8664
        else:
            self.arch = ArchX86()
            self.ql_arch = QL_ARCH.X86

        # Configure the Qiling rootfs path based on the binary's architecture and file type.
        if info.filetype == 11:
            rootfs_path = os.path.join(
                rootfs_path,
                "x8664_windows" if self.arch.POINTER_SIZE == 8 else "x86_windows",
            )
            # on windows the binary must be placed in the rootfs path
            # copy the binary to the rootfs path
            new_binary_path = os.path.join(rootfs_path, binary_name)
            if not os.path.exists(new_binary_path):
                shutil.copy(binary_path, new_binary_path)
            binary_path = new_binary_path

            print(
                "[INFO] For Windows binaries, the Qiling initialization process \
                    can take up to 60 seconds ... Please be patient"
            )
            ida_kernwin.refresh_idaview_anyway()
            time.sleep(0.2)

        elif info.filetype == 18:
            rootfs_path = os.path.join(
                rootfs_path,
                "x8664_linux" if self.arch.POINTER_SIZE == 8 else "x86_linux",
            )

        else:
            show_msgbox("Unsupported file type")
            return

        # Redirect standard output and standard error to the log file.
        with contextlib.redirect_stdout(self.log_file), contextlib.redirect_stderr(self.log_file):
            # Redirect standard input to /dev/null to suppress user input.
            sys.stdin = open(os.devnull, "r")

            # Initialize the Qiling emulator.
            ql = Qiling([binary_path], rootfs_path, log_plain=log_plain)
            self.sym_engine = QilingEngine(ql)
            self.sym_runner = QilingRunner(self.sym_engine, self.ql_arch, debug_level, timeout, symbolic_check)

    def map_segments_to_engine(self):
        """
        Map IDA Pro segments to Qiling's memory.

        This function aligns the segments to the page size and joins adjacent
        segments with the same permissions.
        """
        # Clear existing memory mappings in Qiling.
        self.sym_engine.unmap_all()

        # Get a list of segments in IDA Pro, including their start address, end address, and name.
        segments = [
            (idc.get_segm_start(seg), idc.get_segm_end(seg), idc.get_segm_name(seg)) for seg in idautils.Segments()
        ]

        # Sort segments by their start address.
        segments.sort(key=lambda x: x[0])

        to_map = []
        for start, end, name in segments:
            # Align the start address to the previous segment's end, if available.
            start = max(start, to_map[-1][1] if len(to_map) > 0 else 0)
            # Align the start and end addresses to the page size (4 KB).
            start = (start // 0x1000) * 0x1000
            end = ((end + 0xFFF) // 0x1000) * 0x1000
            size = end - start
            if size > 0:
                to_map.append((start, end, size, name))

        # Join adjacent segments with the same permissions.
        for i in range(len(to_map) - 1):
            if to_map[i] is None:
                continue
            for j in range(i + 1, len(to_map)):
                # if current segment end address is equal to next segment start address
                # merge the segments
                if to_map[i][1] == to_map[j][0]:
                    to_map[i] = (
                        to_map[i][0],
                        to_map[j][1],
                        to_map[j][1] - to_map[i][0],
                        f"{to_map[i][3]}_{to_map[j][3]}",
                    )
                    to_map[j] = None
                    break

        # Remove segments marked for deletion.
        to_map = [seg for seg in to_map if seg is not None]

        print("Registering memory mappings")
        # Map the segments to Qiling's memory.
        for start, end, size, name in to_map:
            self.sym_engine.map(start, size)
            print(hex(start), hex(end), hex(size), name)

            if abs(size) < 0xFFFFFF:
                data = ida_bytes.get_bytes(start, size)
                self.sym_engine.write(start, data)
            else:
                print("Segment too large to copy to Qiling's memory.")

            #  update the start and end address of the text segment
            if ".text" in name:
                self.sym_runner.text_start = start
                self.sym_runner.text_end = end

    def map_registers(self):
        """
        Set up the emulation environment based
        """
        # Get the current execution address as the emulation start.
        emu_start = self.dctx.get_pc()
        self.sym_runner.set_emu_start(emu_start)

        # Set register values based on the current state.
        for regname in self.arch.REGISTERS:
            val = self.dctx.get_reg_value(regname)
            self.sym_runner.set_register(regname, val)
