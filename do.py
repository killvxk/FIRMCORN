s = {"UC_X86_REG_AH ": 1,
"UC_X86_REG_AL ": 2,
"UC_X86_REG_AX ": 3,
"UC_X86_REG_BH ": 4,
"UC_X86_REG_BL ": 5,
"UC_X86_REG_BP ": 6,
"UC_X86_REG_BPL" : 7,
"UC_X86_REG_BX ": 8,
"UC_X86_REG_CH ": 9,
"UC_X86_REG_CL ": 10,
"UC_X86_REG_CS ": 11,
"UC_X86_REG_CX ": 12,
"UC_X86_REG_DH ": 13,
"UC_X86_REG_DI ": 14,
"UC_X86_REG_DIL" : 15,
"UC_X86_REG_DL ": 16,
"UC_X86_REG_DS ": 17,
"UC_X86_REG_DX ": 18,
"UC_X86_REG_EAX" : 19,
"UC_X86_REG_EBP" : 20,
"UC_X86_REG_EBX" : 21,
"UC_X86_REG_ECX" : 22,
"UC_X86_REG_EDI" : 23,
"UC_X86_REG_EDX" : 24,
"UC_X86_REG_EFLAGS" : 25,
"UC_X86_REG_EIP" : 26,
"UC_X86_REG_EIZ" : 27,
"UC_X86_REG_ES ": 28,
"UC_X86_REG_ESI" : 29,
"UC_X86_REG_ESP" : 30,
"UC_X86_REG_FPSW" : 31,
"UC_X86_REG_FS ": 32,
"UC_X86_REG_GS ": 33,
"UC_X86_REG_IP ": 34}
k = {}

for key , value in s.items():
    key_ = key.replace("UC_X86_REG_" , "").lower()
    #print key_ 
    k.update( {key_ : key} )

for i in k.items():
    print i



                "eax":    UC_X86_REG_EAX,
                "ebx":    UC_X86_REG_EBX,
                "ecx":    UC_X86_REG_ECX,
                "edx":    UC_X86_REG_EDX,
                "esi":    UC_X86_REG_ESI,
                "edi":    UC_X86_REG_EDI,
                "ebp":    UC_X86_REG_EBP,
                "esp":    UC_X86_REG_ESP,
                "eip":    UC_X86_REG_EIP,
                "esp":    UC_X86_REG_ESP,
                "efl":    UC_X86_REG_EFLAGS,