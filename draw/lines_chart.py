# encoding=utf-8
from matplotlib import pyplot
import matplotlib.pyplot as plt
 
names = range(8,21)
names = [str(x) for x in list(names)]
 

y_train = [0.840,0.839,0.834,0.832,0.824,0.831,0.823,0.817,0.814,0.812,0.812,0.807,0.805]
y_test  = [0.838,0.840,0.840,0.834,0.828,0.814,0.812,0.822,0.818,0.815,0.807,0.801,0.796]
x_DIR_629_B1 = [4319 , 4320 , 14430 , 53220 , 55454 , 59741, 86400  ]
y_DIR_629_B1 = [0    , 3,     9,      10,     11,   14      , 14    ]

x_DIR_629_A1 = [12539 , 12540 , 49011, 69011, 81434 , 86400 ]
y_DIR_629_A1 = [0 ,     1,      5,     12,     19   , 19   ]

x_DIR_859_A3 = [390 , 391, 1325 , 39201 , 52103 ,  86400 ]
y_DIR_859_A3 = [0 ,   5,   9,     9,      11   ,  11 ]

x_DIR_816_A2 = []
y_DIR_816_A2 = []

x_DIR_823G   = []
y_DIR_823G   = []

x_WR940N     = []
y_WR940N     = []

x_WR941N     = []
y_WR941N     = []

x_HFW5238M   = []
y_HFW5238M   = []

plt.plot(x_DIR_629_B1, y_DIR_629_B1, c="blue" , label='uniprot90_train')
plt.plot(x_DIR_629_A1, y_DIR_629_A1, c="red"  , label='uniprot90_test')
plt.plot(x_DIR_859_A3, y_DIR_859_A3, c="green"  , label='uniprot90_test')

# plt.legend()  # 让图例生效

plt.xlabel('the length') #X轴标签
plt.ylabel("f1") #Y轴标签

plt.show()
# plt.savefig('f1.jpg',dpi = 900)
