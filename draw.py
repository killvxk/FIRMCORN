from pylab import *

x = linspace(0,8,200)

cond = [True if (i>2 and i<5) else False for i in x]

y=sin(x)*(x<2)+cos(x)*cond + x*(x>5)

plot(x,y),show()
