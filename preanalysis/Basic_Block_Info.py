import idaapi
import idautils
import idc
from sets import Set
import logging


class BBInfoExtract():
    def __init__(self , enable_debug = True):
        self.enable_debug = enable_debug
        # self.bb_num = dict()
        self.func_id_list = dict()
        self.func_id = 0
        self.funcs = idautils.Functions()
        fileName = idc.AskFile(1, "*.*", "Extract Binary File Info")
        baseName = idc.GetInputFile()
        self.bb_info_file = open(baseName + ".bb_log",  "w+")


    def get_func_bb(self , func_addr):
        num = 0
        flags = GetFunctionFlags(func_addr)
        dism_addr = list(FuncItems(func_addr))
        for instr in dism_addr:
            if idaapi.is_basic_block_end(instr , False):
                num += 1
        return num

    def get_bb(self):
        for func in self.funcs:
            self.bb_num = dict()
            num = self.get_func_bb(func)
            func_name = GetFunctionName(func)
            self.bb_num.update({func_name:num})
            self.func_id += 1
            self.func_id_list.update({func_name:self.func_id})
            print >> self.bb_info_file, "+++++++++++++++++++++++++++++"
            print >> self.bb_info_file, "Function Name: {}".format(func_name) ,
            print >> self.bb_info_file, "     Function ID: {}".format(self.func_id_list[func_name])
            print >> self.bb_info_file, "    Basic Block Number: {}".format(self.bb_num)
        self.bb_info_file.close()

bb_info = BBInfoExtract()
bb_info = bb_info.get_bb()