#!/usr/bin/env python3
import serial
import sys
import os


def avg(l):
  return sum(l)/len(l)
def med(l):
  l.sort()
  return l[len(l)//2]

dev = serial.Serial("/dev/ttyUSB0", 115200)
res = ''

os.system("make clean && make && make flash")
print("> Returned data:\n")

start = False
while True:
    x = dev.read()
    try:
        s = x.decode('utf-8')
        if not start:
           start = s == 'S'
           continue 
          
        print(s, end='')
        
        if start and s == 'D':
          break        
        res += s
    except:
        pass


clean = [int(x) for x in res.strip().split()]

print(clean)
print(avg(clean))
print(med(clean))

f = open('res', 'w')
f.write("Cycles: "+str(clean))
f.write("Average: "+str(avg(clean))+"\n")
f.write("Median: "+str(med(clean))+"\n")
f.close()



