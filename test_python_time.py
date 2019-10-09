import datetime
oldtime=datetime.datetime.now()
for i in range(10000):
    print "circulation : {}".format(i)



newtime=datetime.datetime.now()
print "time : {}".format( (newtime-oldtime).microseconds )