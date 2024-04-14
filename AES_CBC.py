from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import json

def int_to_bytes(n, byteorder='big'):
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder)

class SymmetricEncryption(object):
    """
    A large number of the schemes can only encrypt group elements
    and do not provide an efficient mechanism for encoding byte in
    those elements. As such we don't pick a symmetric key and encrypt
    it asymmetrically. Rather, we hash a random group element to get the
    symmetric key.

    >>> from charm.toolbox.pairinggroup import extract_key, GT, PairingGroup
    >>> group = PairingGroup('SS512')
    >>> g = group.random(GT)
    >>> key = extract_key(g)
    >>> symencypt = SymmetricEncryption(key)
    >>> msg = b'This is test message!'
    >>> cipher = symencypt.encrypt(msg)
    {"ALG": "AES", "MODE": 2, "IV": 64713035243949218340863336772293828426, "CipherText": 77028219991331294297181772190438510924288161296566000841772397706916366436885}
    >>> decrypt_msg = symencypt.decrypt(cipher)
    b"This is test message!"
    """
    def __init__(self, key, alg = 'AES', mode = AES.MODE_CBC):
        self._alg = alg
        self.key_len = 16
        self._block_size = 16
        self._mode = mode
        self._key = key[0:self.key_len] # expected to be bytes
        assert len(self._key) == self.key_len, "SymmetricCrypto key too short"

    def _initCipher(self,IV = None):
        if IV == None :
            IV =  get_random_bytes(self._block_size)
        self._IV = IV
        return self._key,self._mode,self._IV

    def encrypt(self, message):
        #This should be removed when all crypto functions deal with bytes"
        if type(message) != bytes :
            message = bytes(message, "utf-8")
        ct = self._encrypt(message)
        return ct

    def _encrypt(self, message):
        key, mode, IV = self._initCipher()
        cipher = AES.new(key, mode, IV)
        cpt = cipher.encrypt(pad(message, self._block_size))
        ct= {'ALG': self._alg,
            'MODE': self._mode,
            'IV': self._IV.hex(),
            'CipherText': cpt.hex()
            }
        return ct
        
    def decrypt(self, cipherText):
        return self._decrypt(cipherText)

    def _decrypt(self, cipherText):
        _IV = bytes.fromhex(cipherText['IV'])
        _cpt = bytes.fromhex(cipherText['CipherText'])
        cipher = AES.new(self._key, AES.MODE_CBC, _IV)
        msg = cipher.decrypt(_cpt)
        return unpad(msg, self._block_size)
