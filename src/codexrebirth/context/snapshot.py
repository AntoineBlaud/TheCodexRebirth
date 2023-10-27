

class SnapshotManager():
    
    def __init__(self):
        self.self.snapshot_file = None
        
    def take_ida_execution_snapshot(self):
        # Get the current state of segments and registers
        segments = {}
        for seg in idautils.Segments():
            seg_start = idc.get_segm_start(seg)
            seg_end = idc.get_segm_end(seg)
            if  abs(seg_end - seg_start) < 0xFFFFFF:
                segments[seg] = (seg_start, seg_end, idc.get_bytes(seg_start, seg_end - seg_start))
        
        registers = {}
        for reg in idautils.GetRegisterList():
            try:
                registers[reg] = idc.get_reg_value(reg)
            except:
                pass
        # Create a temporary directory to store the snapshot
        temp_dir = tempfile.mkdtemp()
        # get current binary name
        temp_dir = os.path.join(temp_dir, idc.get_root_filename())
        self.self.snapshot_file = os.path.join(temp_dir, 'ida_snapshot.pkl')
        
        # Serialize and save the data to a file
        with open(self.self.snapshot_file, 'wb') as f:
            snapshot_data = (segments, registers)
            pickle.dump(snapshot_data, f)
        
        print(f"Execution snapshot saved to {self.self.snapshot_file}")
        return os.path.join(temp_dir, 'ida_snapshot.pkl')

    def restore_ida_execution_snapshot(self):
        
        if self.snapshot_file is None:
            # ask the user to select the snapshot file
            self.snapshot_file = ask_file("Select a snapshot file", "(*.pkl)")
            if self.snapshot_file is None or len(config) < 5:
                self.snapshot_file = None
                raise Exception("No config selected")
        
        if not os.path.exists(self.snapshot_file):
            self.snapshot_file = None
            print("Snapshot file not found")
            return
        
        # Deserialize the snapshot data
        with open(self.snapshot_file, 'rb') as f:
            segments, registers = pickle.load(f)
        
        # Restore segments
        i = 0
        for seg, (seg_start, _, seg_data) in segments.items():
            ida_bytes.patch_bytes(seg_start, seg_data)
            i += 1
            print(f"Percentage of segments restored: {i / len(segments) * 100:.2f}%", end='\r')
        
        # Restore registers
        for reg, value in registers.items():
            idc.set_reg_value(value, reg)
        
        print("Execution snapshot restored")
        # Update the snapshot file if it has been correctly restored
        self.self.snapshot_file = self.snapshot_file