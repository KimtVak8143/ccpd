from BlockCipher import BlockCipher
import string
import random
import binascii

block_len = 128

def bits_string_to_int(key):
  return int(key, 2)

def int_to_bits_string(key):
  return "{0:b}".format(key)

def int_to_hex_string(key):
  return format(key, 'x')

def bits_string_to_hex_string(key):
  return int_to_hex_string(bits_string_to_int(key))

def hex_string_to_int(key):
  return int(key, 16)

def init_block(key,ad,msg):
  bit128 = 0 if key.bit_length() > 256  else 1
  bit127 = 0 if ad is None else 1
  bit126 = 0 if msg is None else 1

  b = bit128 << 127 | bit127 << 126 | bit126 << 125 
  return b

def preprocessing(ad,message):
  if (ad.bit_length() == 128) : #need to pad extra 128bits
    ad = ad & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  if ad.bit_length() % 128 !=0 :
    ad = ad & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  if message.bit_length() == 128 : #need to pad extra 128bits
    message = message & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  if message.bit_length() < 128 :
    message = message & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    

def encrypt(key,ad,message):
  
  #preprocessing(ad,message)
  b = init_block(key,ad,message)
  cipher = BlockCipher(key)            #init the block cipher
  tag = cipher.encrypt(b)

  if ad is not None:
    for i in range(ad.bit_length(), 0, -block_len):
      shift_len = i - block_len
      if shift_len < 0:
        shift_len = 0
      tag ^= ((ad >> shift_len) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
      tag = cipher.encrypt(tag)
    if ad.bit_length() == 128 or ad.bit_length() == 0:
      tag = cipher.encrypt(tag)
  result = 0
  if message is not None:
    for i in range(message.bit_length(), 0, -block_len):
      shift_len = i - block_len
      if shift_len < 0:
        shift_len = 0
      tag ^= ((message >> shift_len) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
      tag = cipher.encrypt(tag)
    if message.bit_length() == 128 or message.bit_length() == 0:
      tag = cipher.encrypt(tag)
    counter = 0
    for i in range(message.bit_length(), 0, -block_len):
      curr_tag = tag + counter 
      counter += 1
      encrypted_tag = cipher.encrypt(curr_tag)
      shift_len = i - block_len
      if shift_len < 0:
        shift_len = 0
      encrypted_result = encrypted_tag ^ ((message >> shift_len) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
      result = ((encrypted_result << shift_len) | result )
    if message.bit_length() == 0:
      curr_tag = tag
      encrypted_tag = cipher.encrypt(curr_tag)
      result = encrypted_tag ^ message
  shift_len = result.bit_length() //block_len
  if result.bit_length() % block_len > 0:
    shift_len += 1
  return (tag << (shift_len * block_len) ) | result

def decrypt(key,ad,ct):
  #steps = 128
  cipher = BlockCipher(key)
  shift_len = ct.bit_length() % block_len
  if shift_len == 0:
    shift_len = block_len 
  vv = (ct >> (ct.bit_length() - shift_len)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  pt = None
  if ct.bit_length() > 128:
    pt = 0
    counter = 0
    for i in range((ct.bit_length()-shift_len), 0, -block_len):
      curr_tag = vv + counter
      counter += 1
      encrypted_tag = cipher.encrypt(curr_tag)
      shift_len = i - block_len
      if shift_len < 0:
        shift_len = 0

      pt += ( (encrypted_tag ^ ((ct >> shift_len) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)) << shift_len )
    # pt.append(encrypted_tag ^ ((ct >> shift_len) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))
  # pta =[]
  # for i in range(0, len(pt)):
  #   pta = bin(pt[i])[2:].zfill(128)
  # pta = int(''.join(pta),2)
  b = init_block(key,ad,pt)
  tag = cipher.encrypt(b)

  if ad is not None:
    for i in range(ad.bit_length(), 0, -block_len):
      shift_len = i - block_len
      if shift_len < 0:
        shift_len = 0
      tag ^= ((ad >> shift_len) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
      tag = cipher.encrypt(tag)
    if ad.bit_length() == 128 or ad.bit_length() == 0:
      tag = cipher.encrypt(tag)
  if pt is not None:
    for i in range(pt.bit_length(), 0, -block_len):
      shift_len = i - block_len
      if shift_len < 0:
        shift_len = 0
      tag ^= ((pt >> shift_len) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
      tag = cipher.encrypt(tag)
    if pt.bit_length() == 128 or pt.bit_length() == 0:
      tag = cipher.encrypt(tag)

  if tag != vv:
    return "Tag is not equal to vector"
  else:
    return ["Tag is equal to vector",pt,tag]

if __name__ == "__main__":
  # key = 0x80000000000000000000000000000000
  # ad  = 0x80000000000000000000000000000000
  # message = 0x80000000000000000000000000000000

  # ciphertext = encrypt(key,ad,message)
  # result = decrypt(key,ad,ciphertext)
  # print(result)

  key = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  # ad  = None
  # message = None
  # key = 0
  ad = None
  message = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

  ciphertext = encrypt(key,ad,message)
  result = decrypt(key,ad,ciphertext)
  print(result)
