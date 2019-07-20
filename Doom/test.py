from multiprocessing import *

def f(x :int, y:list):
    for k in y:
        print('x = {}'.format(x))
        print('k = {}'.format(k))
        print(x*k)


p = Pool(5)
p.starmap(f,[(2,[4,5])])