def get_xref_num(func_ea):
    xref_num = 0
    for xref_ea  in CodeRefsTo(func_ea , 0):
        # print analysis result 
        caller_name = GetFunctionName(xref_ea)
        xref_num += 1
    return xref_num


unresolved_funcs = [ 0x5E6F50 , 0x05E6F98 , 0x05E6FDC , 0x05E6FBC , 0x5E7058 , 0x05E7090 ]
unresolved_num = 0
for i in range(len(unresolved_funcs)):
    unresolved_num  += get_xref_num(unresolved_funcs[i])

print "unresolved num {}".format(unresolved_num)

#====================================================
unnecessary_funcs = [ 0x05E7040 , 0x05E6E64 ,  0x05E6E94 , 0x05E6EE8 ]
unnecessary_num = 0

for i in range(len(unnecessary_funcs)):
    unnecessary_num  += get_xref_num(unnecessary_funcs[i])

print "unnecessary num {}".format(unnecessary_num)

#====================================================
hardware_funcs = [ ]
hardware_num = 0

for i in range(len(hardware_funcs)):
    hardware_num  += get_xref_num(hardware_funcs[i])

print "hardware num {}".format(hardware_num)
