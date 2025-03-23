class BreakpointManager:
    def __init__(self, dctx, flog, max_bp):
        self.dctx = dctx
        self.flog = flog
        self.breakpoints_states = {}
        self.max_bp = max_bp

    def set_cached_breakpoint(self, ea):

        if ea not in self.breakpoints_states:

            self.flog(f"Set breakpoint at {hex(ea)}")

            self.dctx.set_breakpoint(ea)
            self.breakpoints_states[ea] = True

    def set_cached_conditional_breakpoint(self, ea, condition, reg):

        if ea not in self.breakpoints_states:

            self.flog(f"Set conditional breakpoint at {hex(ea)} {condition}")

            self.dctx.set_conditional_breakpoint(ea, condition, reg)
            self.breakpoints_states[ea] = True

    def delete_cached_breakpoint(self, ea):

        if ea in self.breakpoints_states:
            
            self.flog(f"Delete cached breakpoint at {hex(ea)}")

            del self.breakpoints_states[ea]
            self.dctx.delete_breakpoint(ea)

    def reset_breakpoints_states(self):

        for bp in self.breakpoints_states:
            self.dctx.delete_breakpoint(bp)

        self.breakpoints_states.clear()

        self.flog("Cleanup breakpoints")


    def set_breakpoints_on_stack(self, stack):
        """Set breakpoints on the given stack."""
        for b_count, target in enumerate(reversed(stack)):

            if b_count > self.max_bp:
                break
            
            self.set_cached_breakpoint(target)


