import gmpy2
from functools import reduce
import itertools
import os

def jugde_prime(num_list):  # 判断是否两两互素
    bnum_pairs=list(itertools.combinations(num_list.values(),2) ) # 两两组合,取字典中键值

    for bnum1,bnum2 in bnum_pairs:
        if gmpy2.gcd(bnum1,bnum2)!=1:  # 求最大公因数，是1则互素
            return False
    return  True

def num_list_inversion(num_list):
    sol_list=[]
    # 求所有模数的累积
    M=reduce(lambda x,y:x*y,num_list.values())

    for a in num_list:
        Mj=M//num_list[a]
        iverm=gmpy2.invert(Mj,num_list[a])  # iver=Mi^(-1) (modmi)
        xj=gmpy2.t_mod(Mj*iverm*a,M)  # xj=Mj*Mj^(-1)*aj (mod M)

        sol_list.append(xj)
    return sol_list,M



def Chinese_Remainder_Theory(num_list):  # num_list:a1,a2,a3,m1,m2,m3
    if not jugde_prime(num_list):
        print("m1,m2,m3 不满足两两互素，不能利用中国剩余定理！")
        return None
    sol_list,M=num_list_inversion(num_list)
    x=reduce(lambda x,y:gmpy2.t_mod(x+y,M),sol_list)   # x=(1-k)+xj(mod M)
    #print("用中国剩余定理求得解为：\nx=%d(mod%d)"%(x,M))
    '''
    for a in num_list:
        index=list(num_list.keys()).index(a)+1
        print('a%d='%index,a)
        print('x(mod m%d)='%index,divmod(x,num_list[a])[1])
    return x,M
    '''
    return x,M

def test(dir):
    '''
    system_of_equations(input): a1:m1,a2:m2,a3:m3
    '''
    for test_f in sorted(os.listdir(dir),key=lambda x:int(x[:-4])):
        print('\n\ntesting %s...'%test_f)
        num_list=open(dir+test_f,'r').read().strip().split('\n')
        if len(num_list)!=6:
            print('Invaid input!')
            continue
        num_list=[gmpy2.mpz(x) for x in num_list] # 转化为大整数形式，有利于提升后面计算速度
        system_of_equations=dict(zip(num_list[:3],num_list[3:]))

        Chinese_Remainder_Theory(system_of_equations)


if __name__=='__main__':
    #dir=r'/Users/apple/Downloads/20个数据/1'
    #test(dir)

    dir=r'/Users/apple/Downloads/1.txt'
    num_list=open(dir,'r').read().strip().split('\n')
    num_list=[gmpy2.mpz(x) for x in num_list] # 转化为大整数形式，有利于提升后面计算速度
    system_of_equations=dict(zip(num_list[:3],num_list[3:]))
    print(system_of_equations)

    Chinese_Remainder_Theory(system_of_equations)


