from cp_abe import abe
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, extract_key
from AES_CBC import SymmetricEncryption
from PIL import Image
import sys
import time
import json

group = PairingGroup('SS512')
cpabe = abe(group)
#Setup algorithm to generate public key PK and master key MK
(pk, mk) = cpabe.setup()
with open('pkmk.txt', 'w') as pkmk:
    pkmk.writelines([json.dumps(pk),'\n', json.dumps(mk)])

#print(pk, mk)
print('----SAVING PK, MK----')
time.sleep(5)
print('----READING PK, MK----')

#Select subtree from tree to generate access policy
'''...'''

#access structure to encrypt message M
access_policy = '((a or b) and (c or d)) and (e or (f or (g and h)))'
#print("Attributes =>", attrs); print("Policy =>", access_policy)
#Encrypt message
'''
group = PairingGroup('SS512')
cpabe = abe(group)
msg = b'1234'
enc_key, cipher = cpabe.encrypt(pk, msg, access_policy)
print(enc_key, cipher)
'''

#Select data type for encryption 
choice = input("""Select data type for encryption:
1: encrypt text file               
2: encrypt pdf file                
3: encrypt image file (png):\n""")
if choice == '1':   #encrypt text file
    with open('data.txt', 'rb') as input_data:
        msg = input_data.read()
elif choice == '2': #encrypt pdf file
    with open('donthuoc.pdf','rb') as input_data:
        msg = input_data.read()
elif choice =='3':  #encrypt image file
    with open('pattern.png', 'rb') as input_data:
        msg = input_data.read()
else:
    print(False)
    sys.exit()
#if debug: print("msg =>", msg)
#print('----STARTING ENCRYPTION----')
time.sleep(5)
group = PairingGroup('SS512')
cpabe = abe(group)
enc_key, cipher = cpabe.encrypt(pk, msg, access_policy)
#print(enc_key, cipher)
print('----SUCCESSFULLY ENCRYPTED----')
#Write encrypted data to file
if choice == '1':   #encrypt text file
    with open('encryped_data.txt', 'w') as enc_data:
        enc_data.write(json.dumps(cipher))
    with open('encrypted_key.txt', 'w') as key:
        key.write(json.dumps(enc_key))

elif choice == '2': #encrypt pdf file
    with open('encrypted_presciption.txt','w') as enc_pre:
        enc_pre.write(json.dumps(cipher))
    with open('encrypted_key.txt', 'w') as key:
        key.write(json.dumps(enc_key))
elif choice =='3':  #encrypt image file
    with open('encrypted_img.png', 'wb') as enc_img:
        input_data.write(bytes.fromhex(cipher['CipherText']))
    with open('encrypted_key.txt', 'w') as key:
        key.write(json.dumps(enc_key))
'''
#Decrypt message
print('----READING PK, MK----')
with open('pkmk.txt', 'r') as pkmk:
    lists = pkmk.readlines()
    pk, mk = json.loads(lists[0]), json.loads(lists[1])
time.sleep(5)
group = PairingGroup('SS512')
cpabe = abe(group)
#print(pk, mk)
def get_pw():
    count = input('Number of attributes:')
    attrs = []
    for i in range(int(count)):
        attrs.append(input('Enter your attributes: ').upper())
    return attrs
#User enter attributes
attrs = get_pw()
print(attrs)
#Generate secret key for decryption
secret_key = cpabe.keygen(pk, mk, attrs)
#print(secret_key)
#Load cipher and ct_key to decrypt
with open('pkmk.txt', 'r') as pkmk:
    lists = pkmk.readlines()
    pk, mk = json.loads(lists[0]), json.loads(lists[1])
print(enc_key)
msg = cpabe.decrypt(pk, secret_key, enc_key, cipher)
print(msg)