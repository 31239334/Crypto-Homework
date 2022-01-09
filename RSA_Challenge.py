# coding=gbk
import gmpy2
import os
import binascii
import itertools
from Algorithm_Base import pollard_p_q,ppl
import math
from Chinese_remainder_theorem import Chinese_Remainder_Theory
import time

def load_file(dir):  # 根据信息格式加载文件
    f=open(dir,'r+')
    data=f.read().strip()
    #print('len of the data:',len(data))
    N=gmpy2.mpz(int('0x'+data[:256],16))
    e=gmpy2.mpz(int('0x'+data[256:256*2],16))
    c=gmpy2.mpz(int('0x'+data[256*2:],16))

    return N,e,c

def RSA_Decryption(c,e,p,q,N):
    d=gmpy2.invert(e,gmpy2.mpz((p-1)*(q-1)))
    m=gmpy2.powmod(c,d,N)
    # print('hex m:',str(hex(m))[2:])
    plaintext=binascii.unhexlify((str(hex(m))[2:]).encode())
    return plaintext

def Fermat_Decomposition(N): # 费马分解法-用来攻击参数选择不当的RSA密文
    """ 当N=p*q选择不当，即p,q过于接近时,可以较快的暴力破解出p,a的值,从而破密 """
    p=pollard_p_q(N)
    if gmpy2.is_prime(p):
        print('p:',p)
        q=N//p
        return p,q
    else:
        return None

def Load_Frames(dir):
    Frame_Info={}
    for test_f in sorted(os.listdir(dir),key=lambda x:int(x[5:])):
        #print('\n\nLoading information about %s...'%test_f)
        N,e,c=load_file(dir+test_f)
        Frame_Info.update({int(test_f[5:]):{'N':N,'c':c,'e':e}})
        #print('N:',N)
        #print('c:',c)
        #print('e:',e)
    return Frame_Info


def Test_Fermat_Decomposition(Frame_Info):
    for frame_num in Frame_Info:
        #print('\n\ntesting %d...'%frame_num)

        cipher_key=Fermat_Decomposition(Frame_Info[frame_num]['N'])
        if cipher_key==None:
            continue
        p,q=cipher_key
        m=RSA_Decryption(Frame_Info[frame_num]['c'],Frame_Info[frame_num]['e'],p,q,Frame_Info[frame_num]['N'])
        print('Crack Successfully!\nFrame %d:\n'%frame_num,m)


def Test_Low_Encryption_Index_Attack(e,frame_index_list,Frame_Info):
    n=math.ceil(512*e/1024)   # 最小可以用低指数攻击的n
    for k in range(n,e+1):
        plaintext=[]
        combs=itertools.combinations(frame_index_list,k)

        for com in combs:
            c=[Frame_Info[fn]['c'] for fn in com]
            N=[Frame_Info[fn]['N'] for fn in com]
            c_N=dict(zip(c,N))

            m,M=Chinese_Remainder_Theory(c_N)

            if gmpy2.iroot(m,k)[1]:
                plaintext.append(gmpy2.iroot(m,k)[0])
        if len(set(plaintext))==1:
            # print(set(plaintext))
            plaintext=binascii.unhexlify(str(hex(plaintext[0]))[2:])
            for fn in frame_index_list:
                print('Frame %d '%fn,end='')
            print(':\n',plaintext[-8:])
            return plaintext
    for fn in frame_index_list:
        print('Frame %d '%fn,end='')
    print('\nDecrypt Failed!')

def egcd(a,b):  # 扩展欧几里得算法
    if a==0:
        return (b,0,1)
    else:
        g,y,x=egcd(b%a,a)
        return (g,x-(b//a)*y,y)

def Test_Common_Modulus_Index_Attack(Frame_Info):  # 公共模攻击
    Ns=[Frame_Info[fn]['N'] for fn in Frame_Info]
    frame_index_list=[]
    for N in set(Ns):
        if Ns.count(N)>=2:
            frame_index_list.append([index for index in Frame_Info if Frame_Info[index]['N']==N])
    print('frame_index_list:',frame_index_list)

    for common_N_frames in frame_index_list:
        for cNf in itertools.combinations(common_N_frames,2):
            e1 = Frame_Info[cNf[0]]['e']
            e2 = Frame_Info[cNf[1]]['e']
            c1 = Frame_Info[cNf[0]]['c']
            c2 = Frame_Info[cNf[1]]['c']
            N = Frame_Info[cNf[0]]['N']

            _,s,t=egcd(e1,e2)
            if s<0:
                s=-s
                c1=gmpy2.invert(c1,N)
            elif t<0:
                t=-t
                c2=gmpy2.invert(c2,N)

            m=pow(c1,s,N)*pow(c2,t,N)%N
            plaintext=binascii.unhexlify(str(hex(m))[2:])
            print('Frame %d ; Frame %d'%(cNf[0],cNf[1]))
            print('plaintext:',plaintext[-8:])

def Factor_Collision_Attack(Frame_Info):
    N=[Frame_Info[fn]['N'] for fn in Frame_Info]
    for N_com in itertools.combinations(N,2):
        if N_com[0]==N_com[1]:     # 在公共模数攻击里面已完成，而且相等的模数也不能用因子碰撞
            continue
        if gmpy2.gcd(N_com[0],N_com[1])!=1:
            p=gmpy2.gcd(N_com[0],N_com[1])
            q1=N_com[0]//p
            q2=N_com[1]//p

            index1=N.index(N_com[0])
            index2=N.index(N_com[1])
            c1=Frame_Info[index1]['c']
            c2=Frame_Info[index2]['c']
            e1=Frame_Info[index1]['e']
            e2=Frame_Info[index2]['e']

            plaintext1=RSA_Decryption(c1,e1,p,q1,N_com[0])
            plaintext2=RSA_Decryption(c2,e2,p,q2,N_com[1])

            print('Frame %d:\n'%index1,plaintext1[-8:])
            print('Frame %d:\n'%index2,plaintext2[-8:])



def Test_Pollard_p_1(Frame_Info):
    for fn in Frame_Info:
        #print('Testing Frame %d...'%fn)
        N=Frame_Info[fn]['N']
        time0=time.time()
        p=ppl(N)
        if p==1:
            #print('p=%d ==> The attack cannot be applied to the Frame.'%p)
            continue
        q=Frame_Info[fn]['N']//p

        c=Frame_Info[fn]['c']
        e=Frame_Info[fn]['e']

        plaintext=RSA_Decryption(c,e,p,q,N)
        print('Frame %d:\n'%fn,plaintext[-8:])


if __name__=='__main__':
    # dir_sample=r'/Users/apple/Downloads/密码挑战赛赛题三/附件3-1（加密案例）/'
    dir_test=r'/Users/apple/Desktop/课程/对称密码/实验报告/18069100135-陈波妃-对称密码分析第四次实验作业/Crypto Challenge Three/附件3-2（发布截获数据）/'
    Frame_Info=Load_Frames(dir_test)

    #print('Frame Information:\n',Frame_Info)
    # 费马因数分解法(测试p,q选取过于接近的不安全情况)
    print("Fermat_Decomposition...")
    Test_Fermat_Decomposition(Frame_Info)
    print("============================================================================================")
    '''
    Crack Successfully!
    Frame 10:
    b'\x98vT2\x10\xab\xcd\xef\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
    \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
    \x00\x00\x00\x00\x00\x00will get'
    去填充:will get
    '''
    #e=[(fn,Frame_Info[fn]['e']) for fn in Frame_Info]
    #print('es:',e)
   
    # 低加密指数攻击
    print("Low_Encryption_Index_Attack...")
    Test_Low_Encryption_Index_Attack(3,[7,11,15],Frame_Info)
    print("============================================================================================")
    '''
    Frame 7 Frame 11 Frame 15 
    Decrypt Failed!
    '''
    # Frame 3,8,12,16,20
    print("Low_Encryption_Index_Attack...")
    Test_Low_Encryption_Index_Attack(5,[3,8,12,16,20],Frame_Info)
    print("============================================================================================")
    '''
    Frame 3 Frame 8 Frame 12 Frame 16 Frame 20 :
    b't is a f'
    '''

    # 公共模数攻击
    print("Common_Modulus_Index_Attack...")
    Test_Common_Modulus_Index_Attack(Frame_Info)
    print("============================================================================================")
    '''
    frame_index_list: [[0, 4]]
    Frame 0 ; Frame 4
    plaintext: b'My secre'
    '''
    
    # 因数碰撞攻击
    print("Factor_Collision_Attack...")
    Factor_Collision_Attack(Frame_Info)
    print("============================================================================================")
    '''
    Frame 1:
    b'. Imagin'
    Frame 18:
    b'm A to B'
    '''
    
    # Pollard p-1分解法
    print("Pollard_p_1 Decomposition...")
    Test_Pollard_p_1(Frame_Info)
    print("============================================================================================")
    '''
    Frame 2:
    b' That is'
    Frame 6:
    b' "Logic '
    Frame 19:
    b'instein.'
    '''
    # 已得：Frame 0,4(公共模数攻击) ; 1,18(因数碰撞) ; 3,8,12,16,20(低加密指数)
    # 10(费马分解法) ; 2,6,19(Pollard p-1分解法) ;
    # 剩下的英文语义推断，互联网查找相关信息资料->采用语义分析和加密验证相结合的方法恢复剩下的明文
