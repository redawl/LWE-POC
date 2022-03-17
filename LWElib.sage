import secrets
import json
import base64
import math
import re
import sys
import pickle

def inner_product(x, y):
    ret = 0
    for i in range(len(x)):
        ret += x[i] + y[i]
    return ret

def to_binary(s):
    return "".join([format(c, '08b') for c in s.encode('utf-8')])

def to_binary_from_bytes(s):
    return "".join([format(c, '08b') for c in s])

def from_binary(b):
    return "".join([chr(int(x,2)) for x in re.findall('........', b)])

class LWE:
    def generate(self, path = os.path.expanduser("~/.LWE")):
        if os.path.exists(path) == False:
            os.mkdirs(path)
        self.q = random_prime(2^128)
        self.m = 48 # Must be a multiple of 8
        self.n = 30
        randoms = []
        for i in range(0, self.m):
            randoms.append([secrets.randbelow(int(self.q)) for x in range(self.n)])

        self.A = matrix(randoms)
        self.e = vector([ secrets.randbelow(math.floor(sqrt(self.q))) for x in range(self.m) ])
        self.sk = vector([secrets.randbelow(int(self.q)) for x in range(self.n)])
        self.pk = (self.A, (self.A * self.sk) + self.e)
            
        with open(f'{path}/LWE.key', 'wb') as file:
            secret_key = b"-----BEGIN LWE PRIVATE KEY-----\n"
            
            secret_key += base64.b64encode(pickle.dumps({"q": self.q, "sk": self.sk }))
            secret_key += b"\n-----END LWE PRIVATE KEY-----\n"
            file.write(secret_key)
        
        with open(f'{path}/LWE.key.pub', 'wb') as file:
            public_key = b"LWE "
            public_key += base64.b64encode(pickle.dumps({"q": self.q, "pk": self.pk })) 
            file.write(public_key)
    
    def load(self, key):
        clear_key = pickle.loads(base64.b64decode(key))
        self.q = clear_key.q
        if sk in clear_key:
            self.sk = clear_key.sk
        else:
            self.pk = clear_key.pk
    
    def encrypt(self, pt): 
        def encrypt_bit(b):
            w = [ int(x) for x in to_binary_from_bytes(secrets.token_bytes(self.m / 8)) ]
            return [vector(w) * self.pk[0], vector(w).dot_product(self.pk[1]) + (b * math.floor(self.q/2))]
        bin = to_binary(pt)

        ct = [encrypt_bit(int(x)) for x in bin ]
        return ct
    
    def decrypt(self, ct):
        def decrypt_bit(b):
            return "0" if abs(b[0].dot_product(self.sk) - b[1]) < math.floor(self.q/2) else "1"

        pt = from_binary(''.join([ decrypt_bit(x) for x in ct ]))
        return pt
        
        return 0
if __name__ == "__main__":
    app = LWE()
    app.generate()
    testing = sys.argv[1]
    print("Testing String: {}".format(testing))
    ct = app.encrypt(testing)
    print("Ciphertext: {}".format(ct))
    pt = app.decrypt(ct)
    print("Plaintext: {}".format(pt))
