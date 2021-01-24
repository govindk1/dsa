from hashlib import blake2b
from Crypto.Util.number import *
from random import *

# Hash of message in blake2b  
def hash_function(message):
    h = blake2b()
    b = bytes(message, 'utf-8')
    h.update(b)
    return h.hexdigest()

# Modular Multiplicative Inverse
def mod_inverse(a, m) : 
    m0 = m 
    y = 0
    x = 1
  
    if (m == 1) : 
        return 0
  
    while (a > 1) : 
  
        # q is quotient 
        q = a // m 
  
        t = m 
  
        # m is remainder now, process 
        # same as Euclid's algo 
        m = a % m 
        a = t 
        t = y 
  
        # Update x and y 
        y = x - q * y 
        x = t 
  
  
    # Make x positive 
    if (x < 0) : 
        x = x + m0 
  
    return x 
    
def maxPrimeFactors(n):
    maxPrime = -1
	
    while n % 2 == 0: 
        maxPrime = 2
        n >>= 1	 
		
    for i in range(3, int(math.sqrt(n)) + 1, 2): 
        while n % i == 0: 
            maxPrime = i 
            n = n / i 
	
    if n > 2: 
        maxPrime = n 
	
    return int(maxPrime)

# Global parameters are p,q and g
def g_calculate(p, q):
    h = randint(1, p-1)
    g = pow(h,int((p-1)/q), p)%p

    if(g == 1):
        return g_calculate(p, q)

    print("random h is: ", h)
    return g;

def parameter_generation():
    p=getPrime(45) 
    q = maxPrimeFactors(p-1)

    print("Prime modulus (p): ",p)
    print("Prime divisor (q): ",q)
        
    h=randint(1, p-1)
    g = g_calculate(p, q)
    
            
    print("Value of g is : ",g)
    
    # returning them as they are public globally
    return (p,q,g)

def per_user_key(p,q,g):
    
    # User private key:
    x=randint(1,q-1)
    print("Randomly chosen x(Private key) is: ",x)

    # User public key:
    y=pow(g,x, p)%p
    print("Randomly chosen y(Public key) is: ",y)

    # returning private and public components
    return(x,y)

def signature(message,p,q,g,x):
    
    hash_component = hash_function(message)
    print("Hash of document sent is: ",hash_component)
    
    r=0
    s=0
    while(s==0 or r==0):
        
        
        k=randint(1,q-1)
        r=((pow(g,k,p))%p)%q
        i=mod_inverse(k,q)

        # converting hexa decimal to binary
        hashed=int(hash_component,16)
        s=((i%q)*((hashed+(x*r))%q))%q

    # returning the signature components
    return(r,s,k)

def verification(message,p,q,g,r,s,y):
    hash_component = hash_function(message)
    print("Hash of document received is: ",hash_component)

    # computing w
    w=mod_inverse(s,q)
    print("Value of w is : ",w)

    
    
    hashed=int(hash_component,16)
    # computing u1, u2 and v
    u1=((hashed%q)*(w%q))%q 
    u2=((r%q)*(w%q))%q 
    v=((pow(g,u1,p)*pow(y,u2,p))%p)%q
    
    print("Value of u1 is: ",u1)
    print("Value of u2 is: ",u2)
    print("Value of v is : ",v)

    if(v==r):
        print("The signature is valid!")
    else:
        print("The signature is invalid!")


global_var=parameter_generation()
keys=per_user_key(global_var[0],global_var[1],global_var[2])

# Sender's side (signing the document):
message = 'This is govind kothari'
components=signature(message,global_var[0],global_var[1],global_var[2],keys[0])

print("r(Component of signature) is: ",components[0])
print("k(Randomly chosen number) is: ",components[2])
print("s(Component of signature) is: ",components[1])

#message = 'THis is it'
# Receiver's side (verifying the sign):
verification(message,global_var[0],global_var[1],global_var[2],components[0],components[1],keys[1])

