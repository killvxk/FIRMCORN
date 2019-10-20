# -*- coding: utf-8 -*-
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter

def to_percent(temp, position):
    return '%1.0f'%(temp) + '%'

X_ = 8
Y_ = 100
xValue = []
yValue = []

datas = {16: [3,2], 1: [2], 2: [9, 4, 3, 3], 3: [2, 1 , 1], 4: [4,1], 6: [3], 8: [12,1]}



maxlen = -1
for k ,v in datas.items():
    xValue.append( k)
    xValue_y = []
    for i in v:
        xValue_y.append( i / (v[0]*1.0) * 100.0 )
    if maxlen < len(xValue_y):
        maxlen = len(xValue_y)
    yValue.append(xValue_y)


for i in range( maxlen):
    yValue_ = []
    for list_ in yValue:
        if  i  >= len(list_):
            yValue_.append(None)
        else:
            yValue_.append( list_[i])
    plt.scatter( xValue , yValue_ ,   facecolors='none', edgecolors='blue')

hight_light_x = []
hight_light_y = []
for k ,v  in datas.items():
    if k == X_:
        hight_light_x.append(k)
        hight_light_y.append(Y_)
    else:
        hight_light_x.append(None)
        hight_light_y.append(None)
plt.scatter( hight_light_x , hight_light_y ,c="red" , s=40)
plt.hlines(80, -1, 1000, colors = "black", linestyles = "dashed")
plt.gca().yaxis.set_major_formatter(FuncFormatter(to_percent))


plt.rcParams['savefig.dpi'] = 3000 
plt.rcParams['figure.dpi'] = 3000

plt.xlabel('Complexity Sort')
plt.ylabel('Vulnerability Ranking Percentage')

plt.ylim(0,110)
plt.xlim(0,300 )
# plt.scatter(xValue , yValue)
plt.show()
