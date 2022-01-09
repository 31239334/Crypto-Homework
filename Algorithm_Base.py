# coding=gbk
import gmpy2

def pollard_p_q(N):
    B=gmpy2.mpz(gmpy2.factorial(2**14))
    a=0;b=0;det=0
    a_=gmpy2.iroot(N,2)[0]+1
    while(det<B):
        a=pow((a_+det),2)-N
        if gmpy2.isqrt(a):
            b=gmpy2.isqrt(a)
            break
        det+=1
    p=a_+det+b

    return p

def ppl(N):
    ''' Pollard p-1分解法 , 适用于p-1或q-1能够被小素数整除的情况 '''
    B=gmpy2.mpz(gmpy2.exp2(20))
    a=2

    for i in range(2,B+1):
        a=gmpy2.powmod(a,i,N)
        d=gmpy2.gcd(a-1,N)
        if d>=2 and d<=(N-1):
            q=N//d
            N=q*d
    return d