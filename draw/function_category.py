import matplotlib.pyplot as plt
import numpy as np

# 构建数据
programs = ['goahead\nDIR-816', 'cgibin\nDIR-629-A1', 'cgibin\nDIR-629-B1', 'cgibin\nDIR-859', 'goahead\nDIR-823G' , 'httpd\nWR940N' , 'httpd\nWR941ND' , 'ezapp\nC6C' , 'sonia\nHFW5238M' , 'sonia\nHFW3236M']
unresolved_num =  [384,   482,  498,  181,    223,  80,   193, 584,  774,  782]
unnecessary_num = [217,   341,  364,  122,    29,   174,  254, 341,  421,  430]
hardware_num =    [1388,  89,  820,  0,     484,  0,    0,   190,  563,  481]


for i in range(len(unresolved_num)):
    unnecessary_num[i] = unnecessary_num[i] + hardware_num[i]
    unresolved_num[i] = unresolved_num[i] + unnecessary_num[i]
# 绘图
widths = []
for i in range(10):
    widths.append(0.4)
plt.bar(x=programs, height=unresolved_num, hatch = "\\\\\\" , width = widths,  label='Unresolved Function', edgecolor='k' ,  color='blue', alpha=1)
plt.bar(x=programs, height=unnecessary_num, hatch = "///" , width = widths,label='Unnecessary Function',  edgecolor='k' ,  color='red', alpha=1)
plt.bar(x=programs, height=hardware_num, hatch = "xxx" , width = widths , label='Hardware-Specific Function',  edgecolor='k' ,  color='green', alpha=1)

# plt.title("Java VS C")
# 为两条坐标轴设置名称
# plt.xlabel("Year")
plt.ylabel("Number")
# 显示图例
# plt.legend( loc = 'upper right')
plt.legend()
# plt.show()

plt.savefig('function_category.png',dpi = 300)