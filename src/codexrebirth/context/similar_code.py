import idautils
import idc
import ida_kernwin
import idaapi
import re
from collections import Counter


class SimilarCodeTool:
    def __init__(self):
        self.colored_instructions = {}

    @staticmethod
    def get_selection():
        ea_start = idc.read_selection_start()
        ea_end = idc.read_selection_end()
        if ea_start == ea_end:
            raise Exception("Please select at least two instructions")
        return (ea_start, ea_end)

    @staticmethod
    def get_disass(ea1, ea2):
        disass = []
        for address in idautils.Heads(ea1, ea2):
            instruction = idc.GetDisasm(address)
            if ";" in instruction:
                instruction = instruction.split(";")[0]
            disass.append((address, instruction))
        return disass

    @staticmethod
    def token_similarity(s1, s2):
        s1 = s1.split("\n")
        s2 = s2.split("\n")
        set1 = set(s1)
        set2 = set(s2)
        intersection = set1.intersection(set2)
        union_size = len(s1) + len(s2)
        counter_s1 = Counter(s1)
        counter_s2 = Counter(s2)
        counter = 0
        for token in intersection:
            counter += counter_s1[token] + counter_s2[token]
        if union_size == 0:
            return 0.0
        similarity = counter / union_size
        return similarity

    @staticmethod
    def get_all_basic_block_disassembly(ea):
        func = idaapi.get_func(ea)
        if not func:
            print("Function not found at 0x{:X}".format(ea))
            return []
        flow_chart = idaapi.FlowChart(func)
        blocks_info = []
        for block in flow_chart:
            block_start = block.start_ea
            block_end = block.end_ea
            block_disassembly = []
            blocks_info.append(SimilarCodeTool.get_disass(block_start, block_end))
        return blocks_info

    @staticmethod
    def get_all_basic_block_bounds(ea):
        func = idaapi.get_func(ea)
        if not func:
            return []
        flow_chart = idaapi.FlowChart(func)
        return [(block.start_ea, block.end_ea) for block in flow_chart]

    def color_similar_instructions(
        self, current_disass, block_disass, similarity_factor, color, comment
    ):
        while len(block_disass) > 0:
            collected_instructions = []
            for (c_ea, current_instruction), (b_ea, block_instruction) in zip(
                current_disass, block_disass
            ):
                similarity = SimilarCodeTool.token_similarity(
                    current_instruction, block_instruction
                )
                if similarity < similarity_factor:
                    break
                else:
                    collected_instructions.append((b_ea, block_instruction))
            if len(collected_instructions) == len(current_disass):
                for ea, instruction in collected_instructions:
                    idc.set_color(ea, idc.CIC_ITEM, color)
                    self.colored_instructions[ea] = True
                idc.set_cmt(collected_instructions[0][0], comment, 0)
                print(
                    "Found similar code at 0x{:X}".format(collected_instructions[0][0])
                )
                block_disass.pop(len(collected_instructions) - 1)
            block_disass.pop(0)

    @staticmethod
    def remove_hardcoded_values(block_disassembly):
        pattern = re.compile(r"[0-9a-fA-F]+h")
        return pattern.sub("", block_disassembly)

    def run(self, similarity_factor, color, comment):
        ea_start, ea_end = SimilarCodeTool.get_selection()
        current_disass = SimilarCodeTool.get_disass(ea_start, ea_end)

        # Specify the address (EA) of the function you want to analyze
        function_address = idc.here()  # Change this to the address of your function

        for block_disass in SimilarCodeTool.get_all_basic_block_disassembly(
            function_address
        ):
            self.color_similar_instructions(
                current_disass, block_disass, similarity_factor, color, comment
            )
            ida_kernwin.refresh_idaview_anyway()
