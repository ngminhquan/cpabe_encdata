from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from charm.toolbox.pairinggroup import PairingGroup,GT, extract_key
from charm.core.math.pairing import pairing,pc_element,ZR,G1,G2,GT,init,pair,hashPair,H,random,serialize,deserialize,ismember,order
from AES_CBC import SymmetricEncryption
import json
# type annotations
pk = { 'g':str, 'h':str, 'f':str, 'e_gg_alpha':str }
mk = {'beta':str, 'g_alpha':str }
secret_key = { 'D':str, 'Dj':str, 'Djp':str, 'S':str }
ct_k =  {'list_att':str, 'Ct':str, 'C':str, 'Cy':str, 'Cyp':str }
cipher = {}
debug = False

def dict_value2hex(dict, groupObj):
    for key, value in dict.items():
        if groupObj.ismember(value):
            dict[key] = groupObj.serialize(value).hex()
    return dict

class abe(ABEnc):
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj

    @Output(pk, mk)
    def setup(self):
        '''
        The setup algorithm takes no input
        It outputs the public parameters PK and a master key MK
        '''
        #choose a bilinear group G1 with genearator g
        #choose two random alpha, beta ∈ Z
        g = group.random(G1)
        alpha, beta = group.random(ZR),group.random(ZR)
        h = g ** beta
        f = g ** ~beta
        e_gg_alpha = pair(g,g**alpha)
        pk = {'g':g, 'h':h,'f':f,'e_gg_alpha':e_gg_alpha}
        pk_hex = dict_value2hex(pk, group)
        mk = {'beta':beta,'g_alpha':g**alpha}
        mk_hex = dict_value2hex(mk, group)
        return pk_hex, mk_hex
    
    def pk_hex2point(self,pk):
        for key, value in pk.items():
            pk[key] = group.deserialize(bytes.fromhex(value))
        return pk
    def mk_hex2point(self, mk):
        for key, value in mk.items():
            mk[key] = group.deserialize(bytes.fromhex(value))
        return mk
    
    @Input(pk, mk, [str])
    @Output(secret_key)
    def keygen(self, pk, mk, S):
        '''
        The key generation algorithm takes as input the master key MK and a set of attributes S
        that describe the key. It outputs a private key SK
        '''
        #Transform pk, mk to point
        pk = self.pk_hex2point(pk)
        mk = self.mk_hex2point(mk)
        #choose random r and rj for each attr j ∈ S.
        r = group.random() 
        g_r = pk['g'] ** r  
        D = (mk['g_alpha']*g_r) ** (1/mk['beta'])
        Dj = {}
        Djp = {}
        for j in S:
            r_j = group.random()
            Dj[j] = g_r * (group.hash(j, G1) ** r_j)
            Djp[j] = pk['g'] ** r_j
        Dj = dict_value2hex(Dj, group)
        Djp = dict_value2hex(Djp, group)
        D = group.serialize(D).hex()
        secret_key = { 'D':D, 'Dj':Dj, 'Djp':Djp, 'S':S }
        return secret_key

    def sk_hex2point(self, sk):
        sk['D'] = group.deserialize(bytes.fromhex(sk['D']))
        for key, value in sk['Dj'].items():
            (sk['Dj'])[key] = group.deserialize(bytes.fromhex(value))
        for key, value in sk['Djp'].items():
            (sk['Djp'])[key] = group.deserialize(bytes.fromhex(value))
        return sk
        
    @Input(pk, bytes, str)
    @Output(ct_k, cipher)
    def encrypt(self, pk, message, policy_str):
        '''
        The encryption algorithm takes as input PK, a message M, and an access structure A over the universe of attributes
        The algorithm will encrypt M and produce a ciphertext CT
        '''
        pk = self.pk_hex2point(pk)
        #Convert string policy to standard type of BinNode
        policy = util.createPolicy(policy_str)
        #BinNode policy => list of attributes
        a_list = util.getAttributeList(policy)
        #s is coef a[0] of root node
        s = group.random(ZR)
        #Compute coef and value of poly q(x) for each node and attributes
        #calculate shares from given secret (a[0] of each poly)
        #returns a dict as {attribute:shares} pairs
        shares = util.calculateSharesDict(s, policy)
        key_point = group.random(GT)
        key = extract_key(key_point)
        #Encrypt input message
        symcrypto = SymmetricEncryption(key)
        cipher = symcrypto.encrypt(message)
        #Encrypt key using ABE
        Ct_key = (pk['e_gg_alpha'] ** s) * key_point
        C = pk['h']**s
        C_y, C_yp = {}, {}
        for i in shares.keys():
            #remove any trailing index or identifier separated by an underscore '_' of attributes
            j = util.strip_index(i)
            C_y[i] = pk['g'] ** shares[i]
            C_yp[i] = group.hash(j, G1) ** shares[i]
        C_y_hex = dict_value2hex(C_y, group)
        C_yp_hex = dict_value2hex(C_yp, group)
        Ct_key_hex = group.serialize(Ct_key).hex()
        C_hex = group.serialize(C).hex()
        ct_k = {'list_att':a_list,'Ct':Ct_key_hex,'C':C_hex,'Cy':C_y_hex,'Cyp':C_yp_hex, 'policy':policy_str}
        return ct_k, cipher
    
    def ct_k_2point(self, ct_k):
        ct_k['Ct'] = group.deserialize(bytes.fromhex(ct_k['Ct']))
        ct_k['C'] = group.deserialize(bytes.fromhex(ct_k['C']))
        for key, value in ct_k['Cy'].items():
            (ct_k['Cy'])[key] = group.deserialize(bytes.fromhex(value))
        for key, value in ct_k['Cyp'].items():
            (ct_k['Cyp'])[key] = group.deserialize(bytes.fromhex(value))
        return ct_k
    @Input(pk, secret_key, ct_k, cipher)
    @Output(bytes)
    def decrypt(self, pk, sk, ct_k, cipher):
        '''
        The decryption algorithm takes as input the public parameters PK, a ciphertext CT, which contains 
        an access policy A, and a private key SK, which is a private key for a set S of attributes.
        If the set S of attributes satisfies the access structure A 
        then the algorithm will decrypt the ciphertext and
        return a message M
        '''
        pk = self.pk_hex2point(pk)
        sk = self.sk_hex2point(sk)
        ct_k = self.ct_k_2point(ct_k)
        #Convert string policy to standard type of BinNode
        policy = util.createPolicy(ct_k['policy'])
        #given policy tree and attributes S, determine whether the attributes satisfy the policy.
        #if not enough attributes to satisfy policy, return None otherwise, 
        #a pruned list of attributes to potentially recover the associated secret.
        pruned_list = util.prune(policy, sk['S'])
        if pruned_list == False:
            return False
        #recover coefficient over a binary tree where possible node types are OR = (1 of 2)
        #and AND = (2 of 2) secret sharing.
        #equivalent to recover coef of q(x) to recursive from leaf to root
        #z:list of larange coef for DecryptNode
        z = util.getCoefficients(policy)
        #A is result of a recursive algorithm from leaf node to root node
        A = 1 
        #i: list of prune attributes
        for i in pruned_list:
            #j:attributes equivalent to each leaf
            #k:attributes after remove index
            j = i.getAttributeAndIndex(); k = i.getAttribute()  
            A *= ( pair(ct_k['Cy'][j], sk['Dj'][k]) / pair(sk['Djp'][k], ct_k['Cyp'][j]) ) ** z[j]
        #Decrypt to receive symmetric key
        key_point = ct_k['Ct'] / (pair(ct_k['C'], sk['D']) / A)
        #Decrypt cipher
        key = extract_key(key_point)
        symcrypto = SymmetricEncryption(key)
        plaintext = symcrypto.decrypt(cipher)
        return plaintext
        #return ct_k['Ct'] / (pair(ct_k['C'], sk['D']) / A)

'''
def cp_abe_encrypt(attrs, msg, pairing_group = 'SS512'):
    cpabe = abe(pairing_group)
    #access structure to encrypt message M
    access_policy = '((a or b) and (c or d)) and (e or (f or (g and h))'
    #print("Attributes =>", attrs); print("Policy =>", access_policy)
    #Setup algorithm to generate public key PK and master key MK
    (pk, mk) = cpabe.setup()
    #Keygen
    secret_key = cpabe.keygen(pk, mk, attrs)
    #Encrypt message
    #if debug: print("msg =>", rand_msg)
    ct = cpabe.encrypt(pk, msg, access_policy)
    return ct
    #decrypt to obtain message
    rec_msg = cpabe.decrypt(pk, secret_key, ct)
    if msg == rec_msg:
        return str(int.from_bytes(group.serialize(rec_msg), byteorder='big'))[:8]
    else:return None
'''