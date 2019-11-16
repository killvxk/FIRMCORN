import matplotlib.pyplot as plt
import numpy as np

# 构建数据
# programs = ['goahead\nDIR-816', 'goahead\nDIR-629-A1',  'cgibin', 'httpd\nDIR-859', 'goahead\nDIR-823G' , 'httpd\nWR940N' , 'httpd\nWR941ND' , 'ezapp' , 'sonia\nHFW5238M' , 'sonia\nHFW3236M']
programs = ['cgibin\nDIR-629-B1', 'cgibin\nDIR-629-A1' , 'cgibin\nDIR-859' , 'goahead\nDIR-816', 'goahead\nDIR-823G',  'httpd\nWR940N',  'httpd\nWR941ND',  'sonia\nHFW5238M' , ]


true_crash = [21 , 11, 39, 53 , 20 ,  7 , 13, 2]
fake_crash = [3 ,  0 , 6 , 23,  17,   3,  0,  0]

for i in range(len(true_crash)):
    fake_crash[i] += true_crash[i]

widths = []
for i in range(8):
    widths.append(0.4)

plt.bar(x=programs, height=fake_crash, hatch = "///" , width = widths,label='False-positives Crashes',  edgecolor='k' ,  color='red', alpha=1)
plt.bar(x=programs, height=true_crash, hatch = "\\\\\\" , width = widths,  label='Vulnerability-led Crashes Reported', edgecolor='k' ,  color='blue', alpha=1)

plt.ylabel("Crash Number")
# 显示图例
# plt.legend( loc = 'upper right')
plt.legend()
plt.rcParams['figure.dpi']=900
plt.show()
# plt.savefig('f2.png',dpi = 500)