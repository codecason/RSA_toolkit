# -*- coding: utf-8 -*-
import sys, random, pickle
import math
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
import json

class RSAMethod():
    def miller_rabin_test( self, a, s, d, n ):
        atop = pow( a, d, n )
        if atop == 1:
            return True
        for i in xrange( s - 1 ):
            if atop == n - 1:
                return True
            atop = ( atop * atop ) % n
        return atop == n - 1

    def miller_rabin( self, n, confidence ):
        d = n - 1
        s = 0
        while d % 2 == 0:
            d >>= 1
            s += 1

        for i in range( confidence ):
            a = 0
            while a == 0:
                a = random.randrange( n )
            if not self.miller_rabin_test( a, s, d, n ):
                return False
        return True

    def euclid_gcd( self, a, b ):
        if a < b:
            a, b = b, a
        while b != 0:
            a, b = b, a % b
        return a

    def ext_euclid( self, a, b ):
        if b == 0:
            return 1, 0, a
        else:
            x, y, gcd = self.ext_euclid( b, a % b )
            return y, x - y * ( a // b ), gcd

    def inverse_mod( self, a, m ):
        x, y, gcd = self.ext_euclid( a, m )
        if gcd == 1:
            return x % m
        else:
            return None

class RSAKey( object ):
    meta = dict( )
    primality_confidence = 20
    rsa = RSAMethod()
    p = 352944073258309558466408983072608193991515297003281401980310731662412492724851063444938790188400068146521572247387094949040379139083567012641806216498789685786517089317916840974536730611084721603339485462863895281872971346067581225794728279
    q = 1136092759942285626181170496180378887643333195182959485781112631657654661430530197139342595364592695103701223860699007113261950658779975266748569195800637185514137564258391752552201910019840704295748743223266987900488193923847879717612548723
    n = p * q
    phi  = (p - 1) * (q - 1)
    e = 154760801700507586546117482929949765460315038125124695315186879911962536186577577834082174195534568122930896354687292186752683432839489447622636599769108269435612464149133226232362076555387063690334333109625765957087529471789778107742556096067063801869144688332040138058470814851099184627947503190916030474712093319549729074253815999524934571086136303127412696908134390834282326744896663722808932699260216895437322698026758401129578128570284509477095028899115206806274068011783161L
    d = 352944677055293829741540943986619082935454893624339937128588726585352767255661898031909724136951806176956770369945789276821524976830904152907825563686782139895399296643020602633674719012188744622006966320973322453021781297733399298655363356610702845985715990211551823968426021848963921294620530718236073879440256838579143733183978553339166718511521973045334542253439912260207119474046992560804513403816162327639534435929425265626420587218605012230971071703511667748353333006697237L
    def setKey(self, modulus, e, d, p, q):
        self.meta = dict()
        self.meta['p'] = p
        self.meta['q'] = q
        self.meta['e'] = e
        self.meta['phi'] = (p - 1) * (q - 1)
        self.meta['modulus'] = modulus
        self.meta['d'] = d
        self.meta.update( { 'pub_key' : ( modulus, e ) } )
        self.meta.update( { 'priv_key' : ( modulus, d ) } )


    def getKey(self):
        key = (self.n, self.e, self.d, self.p, self.q)
        return key

    def gen_keys( self, filename, nbits = 800):
        # generate p ( nbits-bit prime )
        while 1:
            p = random.getrandbits( nbits )
            if self.rsa.miller_rabin( p, self.primality_confidence ):
                self.meta.update( { 'p' : p } )
                print 'nbits are:', p
                break
        # generate q ( nbits-bit prime )
        while 1:
            q = random.getrandbits( nbits )
            if self.rsa.miller_rabin( q, self.primality_confidence ):
                self.meta.update( { 'q' : q } )
                break
        
        # compute modulus: ( p * q )
        modulus = long( self.meta[ 'p' ] * self.meta[ 'q' ] )
        self.meta.update( { 'modulus' : modulus } )

        # compute phi: ( ( p - 1 )( q - 1 ) )
        phi = long( ( self.meta[ 'p' ] - 1 ) * ( self.meta[ 'q' ] - 1 ) )
        self.meta.update( { 'phi' : phi } )

        # choose e s.t 1 < e < phi and euclid_gcd( e, phi ) = 1
        while 1:
            while 1:
                e = random.randrange( phi )
                if e == 0: continue
                if self.rsa.euclid_gcd( e, phi ) == 1:
                    self.meta.update( { 'e' : e } )
                    self.meta.update( { 'pub_key' : ( modulus, e ) } )
                    break
        
            # compute d:
            d = long( self.rsa.inverse_mod( long( self.meta[ 'e' ] ), phi ) )
            if d is None: continue
            else:
                self.meta.update( { 'd' : d } )
                self.meta.update( { 'priv_key' : ( modulus, d ) } )
                break
        if filename != "":
            self.dump( filename, self.meta )
        return self.meta

    def encrypt_file( self, keys_fn, plaintext_fn, ciphertext_fn ):
        self.load( keys_fn )
        plaintext_handle = open( plaintext_fn, 'r' )
        plaintext = plaintext_handle.read( )
        plaintext_handle.close( )
        pub_key = self.meta[ 'pub_key' ]
        ciphertext = ''
        # to be modified:, change the char to be the bytes array and groups
        for char in plaintext:
            print 'char is', char
            ss = str( pow( ord( char ), pub_key[ 1 ], pub_key[ 0 ] ) )
            print ss
            ciphertext += str( pow( ord( char ), pub_key[ 1 ], pub_key[ 0 ] ) ) + '\n'
        print 'finished'
        ciphertext_handle = open( ciphertext_fn, 'w' )
        ciphertext_handle.write( ciphertext )
        ciphertext_handle.close( )
        print 'Wrote encrypted data to: ' + ciphertext_fn

    # TO DELETE
    def decrypt_file( self, keys_fn, ciphertext_fn, decrypted_fn ):
        self.load( keys_fn )
        ciphertext_handle = open( ciphertext_fn, 'r' )
        ciphertext = ciphertext_handle.read( ).split( )
        priv_key = self.meta[ 'priv_key' ]
        decrypted = ''
        for chunk in ciphertext:
            decrypted += chr( pow( long( chunk ), priv_key[ 1 ], priv_key[ 0 ] ) )
        decrypted_handle = open( decrypted_fn, 'w' )
        decrypted_handle.write( decrypted )
        decrypted_handle.close( )
        print 'Wrote decrypted data to: ' + decrypted_fn

    # TO DELETE
    def dump( self, filename, data ):
        try:
            handle = open( filename, 'w' )
            pickle.dump( data, handle )
            handle.close( )
            print 'Wrote generated keys to: ' + str( filename )
        except BaseException as e:
            print e


    # TO DELETE
    def load( self, filename ):
        try:
            handle = open( filename, 'r' )
            self.meta = dict( pickle.load( handle ) )
            handle.close( )
        except BaseException as e:
            print e

    def show_keys( self, keys_fn ):
        try:
            self.load( keys_fn )
            print self.meta
        except BaseException as e:
            print e


    def rsa_encode(self, msg, verbose=False):
        print ""
        chunksize = int(math.log(self.n, 256))
        outchunk = chunksize + 1
        outfmt = '%%0%dx' % (outchunk * 2,)
        bmsg = msg
        result = []
        print 'in rsa encode:'
        print 'outchunk:', repr(outchunk)
        print 'len:', repr(len(bmsg))

        for start in range(0, len(bmsg), chunksize):
            chunk = bmsg[start:start+chunksize]
            chunk += b'\x00' * (chunksize - len(chunk))
            print 'the chunk', repr(chunk)
            plain = int(hexlify(chunk), 16)
            print 'after hexlify:', repr(plain)
            coded = pow(plain, self.e, self.n)
            bcoded = unhexlify((outfmt % coded).encode())
            print 'after unhexlify:', repr(bcoded)
            if verbose: print('Encode:', chunksize, chunk, plain, coded, bcoded)
            result.append(bcoded)
        return b''.join(result)

    def rsa_decode(self, cmsg):
        chunksize = int(math.log(self.n, 256))
        outchunk = chunksize + 1
        outfmt = '%%0%dx' % (chunksize * 2,)
        result = []
        for st in range(0, len(cmsg), outchunk):
            bcoded = cmsg[st:st + outchunk]
            coded = int(hexlify(bcoded), 16)
            plain = pow(coded, self.d, self.n)
            chunk = unhexlify((outfmt % plain).encode())
            result.append(chunk)
        result = b''.join(result).lstrip('\x00')
        result = result.rstrip('\x00')
        print repr(result)
        return result.decode('utf-8')
