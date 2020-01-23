import urllib.request
import base64
from pymd5 import md5, padding
from decimal import *

################################################################################
#
# This starter file for UChicago CMSC 23200 / 33250 is for Python3
#
################################################################################

################################################################################
#
# make_query(task, cnet_id, query)
# -- task should be one of 'one','two','three','four','five'
# -- cnet_id should always be your own cnet_id
# -- query can be any string of bytes, including non-printable
#
################################################################################

def make_query(task, cnet_id, query):
    DEBUG = False; # Replace with "True" to print extra debugging information
    task = task.lower()
    cnet_id = cnet_id.lower()
    if DEBUG:
        print("Querying the server")
        print("(Task:", task, ")")
        print("(CNET ID:", cnet_id, ")")
        print("(Query:", query, ")")
    if (type(query) is bytearray) or (type(query) is bytes):
        url = "http://securityclass.cs.uchicago.edu/" + urllib.parse.quote_plus(task) + "/" + urllib.parse.quote_plus(cnet_id) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query)) + "/"
    else:
        url = "http://securityclass.cs.uchicago.edu/" + urllib.parse.quote_plus(task) + "/" + urllib.parse.quote_plus(cnet_id) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query.encode('utf-8'))) + "/"
    if DEBUG:
        print("(Querying:", url, ")")
    with urllib.request.urlopen(url) as response:
       answer = base64.urlsafe_b64decode(response.read())
       return answer

################################################################################
# Constants for the attacks - Don't change these!
################################################################################

e3 = 65537
k3 = 512
# Modulus N2 is 512 bits long, too short for real security
N3= 0x00dd9387a53d8eb960acc9d3bc49b859e9127ad571f95d3555dc5a30f08b832299d82ecbba38acdadfb4263947f86212f1a3894e3d308545f2618ec3a1cefc5bdf

e4 = 65537
k4 = 512
# Modulus N3 is 512 bits long, too short for real security
N4= 0x00c7d11981bf2838ed5ae602cecc4cffcf141537f9ec6e12b2fcaae43dedbf9845049066cc8720c6685d100957c07e4f5f97b2b8e66d1a3bcc32ecf1e0fee55e6f

#msg4_pract = b'0x8d7ac6d40144d5d1727250791026fa35aad91dc'
msg4_pract = b'0xac3'
#k4= 4
#e4_pract = 3
#N4_pract = 0xb
e4_pract = 65537
N4_pract = 0x00c1cc9b93cb4694f48954b97545a63a7b968c85525049f1c5e70acb31bc23d72978cf94bbb9225772295ee7626a448bef29a04d0822fe4001d714e8ce6c86953d

e5 = 3
k5 = 2048
# Modulus N4 is 2048 bits long
N5 = 0x00bc9e8d81ce1de63e0ab302030e5c0595bf5d2c30fd2660ac9299431a29c4e231a675d684e35415ad87ca738509469aaa0455d62543ab9265d71767f55c7f5fdbb9e2618112212178417c21b4e8a98ab0980fd67864ed7e7e3dcefc3143d5e5d3be2bf0c36c75c977052fedbfdc1c2e448710338fad4fe0e3fa8fc2c662e3466d358df6618dc0a63f45395e5c5aa88d15a49ce2be791acbcd81e28533228918f6abb57e023145a97afea85ad238686f51409017a4d6af8687f7a9438f09a2d9d9e619abdde8e67fc95af23dc97b4a595baa26bfeaf16d31b93e3e1bae1f5813fcd9ef2c8f93df2dd4a779626d07852f120e6b84d936abb811fd4525d9a0cf6621


################################################################################
# Helper methods go below here
################################################################################

#
# modexp(base,exp,modulus) computes (base**exp) % modulus efficiently.
#
# In particular this method can handle very large values of exp, while
# the python builtin ** operator can not.
#
# Feel free to change this if you want, but you probably won't need to.
#
def modexp(base, exp, modulus):
    ret = 1
    while exp > 0:
        if exp % 2 == 1:
            ret = (ret*base) % modulus
        base = (base*base) % modulus
        exp = exp >> 1
    return ret

#your code here


################################################################################
# PROBLEM 1 SOLUTION
################################################################################

def problem1():
    flag = ""
    #your code here
    admin_str = b'&role=admin'
    url_orig = make_query('one', 'hunterythompson', '')
    print(url_orig)
    url_split0 = url_orig.split(b'&')
    url_split1= url_split0[0].split(b'=') #splits string to get md5
    md5dig= url_split1[1]
    #num_bits = len(md5dig) * 8
    #num_blocks = num_bits // 128
        #num_bits_orig = num_blocks * 512
    str0= url_split0[1] + b'&' + url_split0[2] #creates string of uname & role
    print(str0)
    print(md5dig)

    h = md5(state=md5dig, count=512)
    md5dig_admin= h.update(admin_str)
    n_hash = h.hexdigest()
#    print(n_hash)
    n_hashbytes = bytes(h.hexdigest(), 'utf-8')
#    print(n_hashbytes)
    list = []

    for s in range(1, 65):
        padding0 = padding((len(str0)+s)*8)
        url_new = url_split1[0] + b'=' + n_hashbytes +b'&'+ str0 + padding0 + admin_str #build new url
        #if s == 34:
        #    print(bytes.fromhex(n_hash))
        #    print(str0)
        #    print(padding0)
        #    print(url_new)
        list.append(make_query('one', 'hunterythompson', url_new))
            #print(url_new.decode("utf-8"))
        if (str(make_query('one', 'hunterythompson', url_new), 'utf-8') == 'Incorrect hash'):
            continue
        else:
            print(list)
            print(make_query('one', 'hunterythompson', url_new))
            return make_query('one', 'hunterythompson', url_new)
    print(list)
    return


################################################################################
# PROBLEM 3 SOLUTION
################################################################################

def problem3():
    flag = ""
    #your code here
    c_text = make_query('three', 'hunterythompson', '')
    print(c_text)

    c_int = int(c_text, 0)
    #print(c_int)
    nullbyte = modexp(256, e3, N3) #256 is 2^8 to shift left  by 8 bites (NULL byte)
    c_new0 = nullbyte * c_int
    c_new = c_new0 % N3
    flag = make_query('three', 'hunterythompson', hex(c_new))
    return flag


################################################################################
# PROBLEM 4 SOLUTION
################################################################################

def problem4():
    flag = ""
    #your code here
    c_text = make_query('four', 'hunterythompson', '') #takes in ciphertext
    c_int = int(c_text, 0) #converts to int
    getcontext().prec = 512
    #msg_int = int(msg4_pract, 0)
    #print(msg_int)
    #c_int = modexp(msg_int, e4_pract, N4_pract)
    #print("c_int is ", c_int)
    low = Decimal(0)
    upp = Decimal(N4)
    upp_num = 1
    for s in range(1, k4 + 1):
        #print("upp_num is", upp_num)
        two_mult = 2**s
        two_add = modexp(two_mult, e4, N4)
        #print(two_mod)
        c_new0 = c_int * two_add
        two_mod = make_query('four', 'hunterythompson', hex(c_new0))
        #print(c_new0)
        #c_new1 = c_new0 % N4_pract
        #print(c_new1)
        #c_new1 = c_new1 % 2
        #print(c_new1)
        if two_mod == 0:
            upp = Decimal(upp_num) * Decimal(N4)/ Decimal(2**s)
            #print("New upper is ", upp)
            upp_num = (upp_num * 2) - 1
            #print(s, "is 0")
        else:
            low = Decimal(upp_num) * Decimal(N4)/ Decimal(2**s)
            #print("New lower is ", low)
            upp_num = (upp_num * 2) + 1
            #print(s," is 1")
    #print(upp)
    #print(low)
    upp_int = upp.to_integral_value()
    low_int = low.to_integral_value()
    print(upp_int)
    print(low_int)
    print("The difference bw low & upp is", (upp_int-low_int))
    c_low = modexp(low_int, e4, N4)
    c_upp = modexp(upp_int, e4, N4)
    print(c_low)
    print(c_upp)
    print(c_int)
    if c_int == c_low:
        print("yay!")
    elif c_int == c_upp:
        print("SpOoKy!")
    else:
        print("better luck chick")
    return flag

################################################################################
# PROBLEM 5 SOLUTION
################################################################################

def problem5():
    flag = ""
    #your code here
    getcontext().prec = 2000

    sha256 = b'9c29e443b37afa015fafc09aac96e19fbb58d7f183b68b6630ccfcadf17f8350'
    X_byte = b'0001ff00' + sha256
    f_byte1 = b'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    X_byte_large = X_byte + f_byte1 + f_byte1
    X_int = int(X_byte, 16)
    X_large_int = int(X_byte_large, 16)
    X_int_fcrt = Decimal(X_int**(1./3.)) #take cube root of smallest value in range
    X_cbrt = X_int_fcrt.to_integral_value() #+ Decimal(1) #add 1 to int val of cube root
    X_cbrt_new = X_cbrt + 1
    print(X_cbrt)
    print(X_cbrt_new)
    print(X_cbrt_new - X_cbrt)
    X_old = X_cbrt ** 3
    X_new = X_cbrt_new ** 3
    X_old_int = int(X_old)
    X_int1 = int(X_new)
    print(hex(X_int1))
    print(hex(X_old_int))
    print(make_query('five', 'hunterythompson', hex(X_int1)))

    return flag



# below here will be run if you execute 'python3 assignment1.py'
# use this for testing by uncommenting the lines for problems you wish to test
if __name__ == "__main__":
    #print("Problem 0 flag:", problem0())
    #print("Problem 1 flag:", problem1())
    #print("Problem 2 flag:", problem2())
    #print("Problem 3 flag:", problem3())
    #print("Problem 4 flag:", problem4())
    print("Problem 5 flag:", problem5())
    exit()
