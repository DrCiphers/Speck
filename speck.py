"""Pure-Python Speck implementation Class."""
"""created by Iosifidis Efthimios         """

def new(key, IV):
    return Python_SPECK(key, mode, IV,implementation)


class Python_SPECK():
    
    def __init__(self, key, IV):
        
        self.isBlockCipher = True
        self.isAEAD = False
        self.block_size = 128
        self.implementation = 'python'
        self.key = key
        self.IV = IV
        self.rounds = 32
        self.word_size = 64
        self.k = list()
        self.key_words = 2
        
        # Create Properly Sized bit mask for truncating addition and left shift outputs
        self.mod_mask = (2 ** self.word_size) - 1        
        
        #The following parameters are valid when having SPECK with 128bits size blocks and 128 bit key size
        self.alpha_shift = 8
        self.beta_shift = 3
        
        
        # Parse the given key and truncate it to the key length
        try:
            self.key = key & ((2 ** 128) - 1)
        except (ValueError, TypeError):
            print('Invalid Key Value!')
            print('Please Provide Key as int')
            raise

        # Pre-compile key schedule
        self.key_schedule = [self.key & self.mod_mask]
        l_schedule = [(self.key >> (x * self.word_size)) & self.mod_mask for x in
                      xrange(1, 128 // self.word_size)]

        for x in range(self.rounds - 1):
            new_l_k = self.encrypt_round(l_schedule[x], self.key_schedule[x], x)
            l_schedule.append(new_l_k[0])
            self.key_schedule.append(new_l_k[1])
            
            
        
    def add(self, x, y):
        return (x+y)%(1<<64)       
       
       
    # ROR(x, r) ((x >> r) | (x << (64 - r)))
    def ROR(self,x):
        rs_x = ((x >> self.alpha_shift) | (x << (self.word_size - self.alpha_shift)))& self.mod_mask
        return rs_x


    #ROL(x, r) ((x << r) | (x >> (64 - r)))
    def ROL(self,x):
        ls_x = ((x << self.beta_shift) | (x >> (self.word_size - self.beta_shift)))& self.mod_mask
        return ls_x


    # ROR(x, r) ((x >> r) | (x << (64 - r)))
    def ROR_inv(self,x):
        rs_x = ((x >> self.beta_shift) | (x << (self.word_size - self.beta_shift)))& self.mod_mask
        return rs_x


    #ROL(x, r) ((x << r) | (x >> (64 - r)))
    def ROL_inv(self,x):
        ls_x = ((x << self.alpha_shift) | (x >> (self.word_size - self.alpha_shift)))& self.mod_mask
        return ls_x


    def bytesToNumber(self,b):
        total = 0
        multiplier = 1
        for count in range(len(b)-1, -1, -1):
            byte = b[count]
            total += multiplier * byte
            multiplier *= 256
        return total


    def numberToByteArray(self,n, howManyBytes=None):
        """Convert an integer into a bytearray, zero-pad to howManyBytes.
    
        The returned bytearray may be smaller than howManyBytes, but will
        not be larger.  The returned bytearray will contain a big-endian
        encoding of the input integer (n).
        """    
        if howManyBytes == None:
            howManyBytes = numBytes(n)
        b = bytearray(howManyBytes)
        for count in range(howManyBytes-1, -1, -1):
            b[count] = int(n % 256)
            n >>= 8
        return b


    # define R(x, y, k) (x = ROR(x, 8), x += y, x ^= k, y = ROL(y, 3), y ^= x)
        
    def encrypt_round(self, x, y, k):
        #Feistel Operation
        new_x = self.ROR(x)   #x = ROR(x, 8)
        new_x = (new_x + y) & self.mod_mask
        new_x = k ^ new_x
        new_y = self.ROL(y)    #y = ROL(y, 3)
        new_y = new_x ^ new_y

        return new_x, new_y
    

    def decrypt_round(self, x, y, k):
        #Inverse Feistel Operation
                
        xor_xy = x ^ y     
        new_y = self.ROR_inv(xor_xy) 
        xor_xk = x ^ k

        msub = (xor_xk - new_y) & self.mod_mask
        new_x = self.ROL_inv(msub) 

        return new_x, new_y
   
  
    
    def encrypt(self, plaintext):        
        
        
        if len(plaintext)*8 != self.block_size:
            raise ValueError('wrong block length, expected ' + str(self.block_size) + ' got ' + str(len(plaintext)))             

        plaintext = self.bytesToNumber(plaintext)
        
       
        b = (plaintext >> self.word_size) & self.mod_mask
        a = plaintext & self.mod_mask
        
        for x in self.key_schedule:
            b, a = self.encrypt_round(b, a, x)

        
        ciphertext = (b << self.word_size) | a
        
        return ciphertext
        
        
        
    def decrypt(self, ciphertext):
        
        b = (ciphertext >> self.word_size) & self.mod_mask
        a = ciphertext & self.mod_mask        
       
        for x in reversed(self.key_schedule):
            b, a = self.decrypt_round(b, a, x)
      
        plaintext = (b << self.word_size) | a    
            
        return plaintext



if __name__== '__main__':
    
    plaintext = bytearray("HelloWorld!Hello90jg390g934jg349jg390-g349-gj34-9gj3490-gj349333")

    print("Initial Plaintext:%s"%plaintext)
    print

    s =  Python_SPECK(1234567890123456, 0)
    

    
    for x in range(len(plaintext)//16):
        #XOR with the chaining block
        blockBytes = plaintext[x*16 : (x*16)+16]
       
        print("Plaintext: %s"%blockBytes)
        print("Plaintext converted to int: %s"%s.bytesToNumber(blockBytes))
        
        ciphertext = s.encrypt(blockBytes)
        print("Cipher Block:%s"%ciphertext)
        
        Recovered_plaintext=s.decrypt(ciphertext)
        print("Decrypted Cipher Block: %s"%Recovered_plaintext)
        
        print("Recoverd Plaintext: %s"%s.numberToByteArray(Recovered_plaintext,howManyBytes=16))
        print
