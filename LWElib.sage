import secrets
import json
import base64
import math
import re
import sys

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
    def __init__(self):
        self.q = random_prime(2^512)
        self.m = 48
        self.n = 30
    def generate(self):
        randoms = []
        for i in range(0, self.m):
            randoms.append([x % self.q for x in secrets.token_bytes(self.n)])

        self.A = matrix(randoms)
        self.e = vector([ x % math.floor(sqrt(self.q)) for x in secrets.token_bytes(self.m) ])
        self.sk = vector([x % self.q for x in secrets.token_bytes(self.n)])
        self.pk = (self.A, (self.A * self.sk) + self.e)
        with open('LWE.key', 'wb') as file:
            secret_key = "---------------------------- BEGIN PRIVATE KEY ----------------------------\n{}\n".format(self.n)
            secret_key += ''.join([ '{} '.format(x) for x in self.sk ])
            secret_key += "\n---------------------------- END PRIVATE KEY ----------------------------\n"
            file.write(secret_key.encode())
        
        with open('LWE.key.pub', 'wb') as file:
            public_key ="---------------------------- BEGIN PUBLIC KEY ----------------------------\n{}\n{}".format(self.n, self.m)
            for i in self.pk[0]:
                for j in i:
                    public_key = '{}{} '.format(public_key, j)
            public_key += ''.join([ '{} '.format(x) for x in self.pk[1] ])
            public_key += '\n---------------------------- END PUBLIC KEY ----------------------------\n'
            file.write(public_key.encode())

    def encrypt(self, pt): 
        def encrypt_bit(b):
            w = [ int(x) for x in to_binary_from_bytes(secrets.token_bytes(self.m / 8)) ]
            return [vector([x for x in w ]) * self.pk[0], vector(w).dot_product(self.pk[1]) + (b * math.floor(self.q/2))]
        bin = to_binary(pt)

        ct = [encrypt_bit(int(x)) for x in bin ]
        return ct
    
    def decrypt(self, ct):
        def decrypt_bit(b):
            return str(0) if abs(b[0].dot_product(self.sk) - b[1]) < math.floor(self.q/2) else str(1)

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
