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

    url_split0 = url_orig.split(b'&')
    url_split1= url_split0[0].split(b'=') #splits string to get md5
    md5dig= url_split1[1]

    str0= url_split0[1] + b'&' + url_split0[2] #creates string of uname & role

    md5dig = bytes.fromhex(md5dig.decode('utf8')) #convert to bytes to make state
    h = md5(state=md5dig, count=512) #set state of md5 for future
    md5dig_admin= h.update(admin_str) #make new md5 hash
    n_hash = h.hexdigest()

    n_hashbytes = bytes(h.hexdigest(), 'utf-8')


    for s in range(1, 65):
        padding0 = padding((len(str0)+s)*8) #make padding for string
        url_new = url_split1[0] + b'=' + n_hashbytes +b'&'+ str0 + padding0 + admin_str #build new url

        if (str(make_query('one', 'hunterythompson', url_new), 'utf-8') == 'Incorrect hash'):
            continue
        else:
            return make_query('one', 'hunterythompson', url_new)
    return


################################################################################
# PROBLEM 3 SOLUTION
################################################################################

def problem3():
    flag = ""
    #your code here
    c_text = make_query('three', 'hunterythompson', '')
    c_int = int(c_text, 0)
    nullbyte = modexp(256, e3, N3) #256 is 2^8 to shift left  by 8 bites (NULL byte)
    c_new0 = nullbyte * c_int #multiply 2 ciphers together
    c_new = c_new0 % N3 #mod N3
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
    getcontext().prec = k4 #set precision of decimals
    low = Decimal(0)
    upp = Decimal(N4)
    upp_num = 1 #Multiply numerator by this number to get new upper/lower bound
    for s in range(1, k4 + 1):
        two_mult = 2**s #Multiple of 2 to check next bit
        two_add = modexp(two_mult, e4, N4)
        c_new0 = c_int * two_add
        two_mod = make_query('four', 'hunterythompson', hex(c_new0)) #query to return 0 or 1
        if two_mod == b'\x00': #if bit is 0, adjust upper bound
            upp = (Decimal(upp_num) * Decimal(N4))/ Decimal(2**s)
            upp_num = (upp_num * 2) - 1

        else: #if bit is 1, adjust lower bound
            low = (Decimal(upp_num) * Decimal(N4))/ Decimal(2**s)
            upp_num = (upp_num * 2) + 1

    upp_int = upp.to_integral_value()
    low_int = low.to_integral_value()

    c_low = modexp(low_int, e4, N4) #calculate ciphertext of lower bound
    c_upp = modexp(upp_int, e4, N4) #calculate ciphertex of upper bound

    if c_int == c_low: #check to see if ciphertext = calculated lower cipher
        flag = low_int
        return flag
    elif c_int == c_upp: #check to see if ciphertext = calculated lower cipher
        flag = upp_int
        return flag
    else:
        return flag

################################################################################
# PROBLEM 5 SOLUTION
################################################################################

def problem5():
    flag = ""
    #your code here
    getcontext().prec = 2000

    sha256 = b'9c29e443b37afa015fafc09aac96e19fbb58d7f183b68b6630ccfcadf17f8350' #sha256 of cnet_id
    X_byte = b'0001ff00' + sha256
    f_byte1 = b'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    f_byte0 = b'0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    X_byte_small = X_byte + f_byte0 + f_byte0
    X_byte_large = X_byte + f_byte1 + f_byte1
    X_int = int(X_byte_small, 16)
    X_large_int = int(X_byte_large, 16)
    X_int_fcrt_low = Decimal(X_int) #take cube root of smallest value in range
    X_int_fcrt_low = X_int_fcrt_low ** (Decimal(1)/Decimal(3))
    X_int_fcrt_hgh = Decimal(X_large_int) #take cube root of smallest value in range
    X_int_fcrt_hgh = X_int_fcrt_hgh ** (Decimal(1)/Decimal(3))
    X_cbrt = (X_int_fcrt_hgh + X_int_fcrt_low) / Decimal(2) #take avg of two cube roots
    X_cbrt = X_cbrt.to_integral_value() # Convert to integer value

    return make_query('five', 'hunterythompson', hex(int(X_cbrt)))



# below here will be run if you execute 'python3 assignment1.py'
# use this for testing by uncommenting the lines for problems you wish to test
if __name__ == "__main__":
    #print("Problem 0 flag:", problem0())
    print("Problem 1 flag:", problem1())
    #print("Problem 2 flag:", problem2())
    print("Problem 3 flag:", problem3())
    print("Problem 4 flag:", problem4())
    print("Problem 5 flag:", problem5())
    exit()
