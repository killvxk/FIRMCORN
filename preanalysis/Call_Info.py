import idaapi
import idautils
import idc
from sets import Set
import logging


class CallInfoExtract():
    def __init__(self , enable_debug = True):
        self.enable_debug = enable_debug
        # caller func init
        self.callees = dict()
        self.caller_func_id_list = dict()
        self.caller_func_id = 0
        self.caller_func_num = 0
        # sub func init
        self.sub_func_id_list = dict()
        self.sub_func_id = 0
        self.sub_func_num = 0

        fileName = idc.AskFile(1, "*.*", "Extract Binary File Info")
        baseName = idc.GetInputFile()
        self.funcs = idautils.Functions()
        self.caller_func_file = open( baseName + ".caller_func_log" , "w+")
        self.sub_func_file = open(baseName + ".sub_func_log" , "w+")

    def get_caller_func(self):
        if self.enable_debug == True:
            print type(self.funcs)
            print self.funcs

        for func in self.funcs:
            func_name = GetFunctionName(func)
            self.caller_func_id_list.update({func_name:self.caller_func_id})
            self.caller_func_num += 1
            self.caller_func_id  += 1
            if self.enable_debug == True:
                print type(func)
                print func
            print >> self.caller_func_file, "+++++++++++++++++++++++++++++"
            print >> self.caller_func_file, "Function Name: {}".format(func_name) ,
            print >> self.caller_func_file, "     Function ID: {}".format(self.caller_func_id_list[func_name])
            print >> self.caller_func_file, "    caller_func:"
            for ref_ea in CodeRefsTo(func , 0):
                caller_name = GetFunctionName(ref_ea)
                print caller_name
                self.callees[caller_name] = self.callees.get(caller_name, Set())
                self.callees[caller_name].add(func_name)
                print >> self.caller_func_file , "        {}".format(caller_name)
        self.caller_func_file.close()

    def get_apis(self , func_addr):
        calls = 0
        apis = []
        flags = GetFunctionFlags(func_addr)
        # ignore library functions
        # if flags & FUNC_LIB or flags & FUNC_THUNK:
        #     logging.debug("get_apis: Library code or thunk")
        #     return None
        # list of addresses
        dism_addr = list(FuncItems(func_addr))
        for instr in dism_addr:
            tmp_api_address = ""
            if idaapi.is_call_insn(instr):
                # In theory an API address should only have one xrefs
                # The xrefs approach was used because I could not find how to
                # get the API name by address.
                for xref in XrefsFrom(instr, idaapi.XREF_FAR):
                    if xref.to == None:
                        calls += 1
                        continue
                    tmp_api_address = xref.to
                    break
                # get next instr since api address could not be found
                if tmp_api_address == "":
                    calls += 1
                    continue
                api_flags = GetFunctionFlags(tmp_api_address)
                # check for lib code (api)
                if api_flags & idaapi.FUNC_LIB == True or api_flags & idaapi.FUNC_THUNK:
                    tmp_api_name = NameEx(0, tmp_api_address)
                    if tmp_api_name:
                        apis.append(tmp_api_name)
                else:
                    calls += 1
        if len(apis):
            return apis
        else:
            return []


    def get_sub_func(self):
        # xref_froms = []
        # print self.funcs
        for func  in self.funcs:
            print hex(func)
            func_name = GetFunctionName(func)
            self.sub_func_id_list.update({func_name:self.sub_func_id})
            self.sub_func_num += 1
            self.sub_func_id += 1
            dism_addr = list(idautils.FuncItems(func))
            print >> self.sub_func_file, "+++++++++++++++++++++++++++++"
            print >> self.sub_func_file, "Function Name: {}".format(func_name) ,
            print >> self.sub_func_file, "     Function ID: {}".format(self.sub_func_id_list[func_name])
            print >> self.sub_func_file, "    sub_func:"
            apis = self.get_apis(func)
            for i in range(len(apis)):
                # print >> self.sub_func_file , "        {}".format(type(apis[i]))
                print >> self.sub_func_file , "        {}".format(apis[i])
            # try:
            #     apis = get_apis(func)
            #     if apis is None:
            #         continue

            # except:
            #     continue
        self.sub_func_file.close()

idc.Wait()
call_info = CallInfoExtract()
call_info.get_sub_func()