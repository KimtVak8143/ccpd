import sys
import pickle
from functools import reduce
from operator import xor
import string
import random
from time import gmtime, strftime
from datetime import datetime
import secrets
import binascii

rounds = 13
sbox     = [0x0, 0xF, 0xB, 0x8, 0xC, 0x9, 0x6, 0x3, 0xD, 0x1, 0x2, 0x4, 0xA, 0x7, 0x5, 0xE]
sbox_inv = [0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1]    
pbox     = [1, 2, 9, 4, 15, 6, 5, 8, 13, 10, 7, 14, 11, 12, 3, 0]
pbox_inv = [15, 0, 1, 14, 3, 6, 5, 10, 7, 2, 9, 12, 13, 8, 11, 4]

class BlockCipher:
  def __init__(self, key):
    self.print = True

    if key is None:
      raise ValueError("Key must not be None")
    else:
      self.master_key_size = 128
      if key.bit_length() > 128:
        self.master_key_size = ( key.bit_length() // 64 ) * 64
        if key.bit_length() % 64 > 0:
          self.master_key_size += 64 
      self.master_key = key
    self.keys = self.generateRoundKeys()

  def sBoxLayerInverse(self,state):
    sub_block = ""
    for i in range(len(state)):
      sub_block += str(hex(sbox_inv[int(state[i], 16)])[2])
    return int(sub_block, 16)

  def pBoxLayer(self,ct): #expecting string
    perm_list = [0 for x in range(16)]  # put 16 zeros in perm_list
    perm_block = []

    while ct:
      split_block = ct[:4]
      prep_permutate = bin(int(split_block,16))[2:].zfill(16)
      for i in range(len(prep_permutate)):
        perm_list[pbox[i]] = prep_permutate[i]
      perm_block.append(int(''.join(perm_list),2))
      ct = ct[4:]
    
    return perm_block

  def XORLayer(self,state): #expecting int array
    for i in reversed(range(len(state))):
      state[i-1] = state[i-1] ^ state[i]

  def shiftLayer(self,state):
    for i in range(len(state)):
      state[i] = bin(state[i])[2:].zfill(16)
      if i == 0 or i == 4:
        state[i] = state[i][9:] + state[i][:9]    # left circular shift 9 bits

      elif i == 1 or i == 5:
        state[i] = state[i][7:] + state[i][:7]    # left circular shift 7 bits

      elif i == 2 or i == 6:
        state[i] = state[i][4:] + state[i][:4]    # left circular shift 4 bits

      elif i == 3 or i == 7:
        state[i] = state[i][1:] + state[i][:1]    # left circular shift 1 bits
    # ''.join(state)

  def sBoxLayer(self,state):
    sub_block = ""
    for i in range(len(state)):
      sub_block += str(hex(sbox[int(state[i], 16)])[2])
    return int(sub_block, 16)

  def xorcounter(self,string, count):
    y = '{0:05b}'.format(int(string, 2) ^ count)
    return y

  def substitute(self,s):
    subs_block = ""
    s = hex(int(s, 2))
    subs_block += str(hex(sbox[int(s, 16)])[2])
    subs_block = int(subs_block, 16)
    x = '{0:04b}'.format(subs_block)
    return x
  
  def generateRoundKeys(self):
    subs_set = int((self.master_key_size-128) / 64) % 4
    K = []  # list of 128 bit keys for 13 rounds.
    string = bin(self.master_key)[2:].zfill(128)
   
    for i in range(0, 13):
      string = string[13:] + string[:13] #shift by 13bits
      if subs_set == 0 :
        string = string[:124] + self.substitute(string[124:]) #eg substitute 4 LSB bits if key = 128 bits
      elif subs_set == 1 :
        string = string[:120] + self.substitute(string[120:124]) + string[124:]#eg substitute subsequent +4 LSB bits if key = 192bits
      elif subs_set == 2 :
        string = string[:116] + self.substitute(string[116:120]) + string[120:] #
      elif subs_set == 3 :
        string = string[:112] + self.substitute(string[112:116]) + string[116:] #

      string = self.xorcounter(string[:5],i+1) + string[5:] #XOR 5 MSB bits with ctr
      K.append(int(string[0:128], 2))
    return K

  def addRoundKey(self, ct, key):
    x = ct ^ key
    return x

  def encrypt(self, ct):
    for i in range(rounds):
      # XOR with Key
      ct = self.addRoundKey(ct, self.keys[i])

      # SBox
      ct = hex(ct)[2:].zfill(32)  # change int decimal to string hex/ zfill , fills zeros until the size is 16
      ct = self.sBoxLayer(ct)

      # PBox
      ct = self.pBoxLayer(hex(ct)[2:].zfill(32))

      #XOR with blocks
      self.XORLayer(ct)

      #Shift block
      self.shiftLayer(ct)
      ct = int(''.join(ct),2)
      
    return ct

  def encrypt_from_int(self,text):
    self.text_key_size = (text).bit_length()
    return self.encrypt(text)
  
  def encrypt_from_hex(self,text):
    self.text_key_size = len(text)*4
    return self.__encrypt(self.hex_string_to_int(text))
  
  def encrypt_to_hex(self,text):
    return self.int_to_hex_string(self.encrypt_from_hex(text)).zfill(self.text_key_size//4)

  def __decrypt(self,text_key):
    for x in range(1, self.round + 1, 1):
      curr_key = 0
      for i in range(0, self.text_key_size, 64):
        first_set  = (text_key >> i) & 0xFFFF
        second_set = (text_key >> i+16) & 0xFFFF
        third_set  = (text_key >> i+32) & 0xFFFF
        fourth_set = (text_key >> i+48) & 0xFFFF
        fourth_set ^= third_set
        first_set  ^= second_set
        second_set ^= fourth_set
        third_set  ^= first_set
        curr_key |= ((fourth_set << (i + 48)) |  (third_set  << (i + 32)) |  (second_set << (i + 16)) | (first_set  << i))
      text_key = curr_key
      shift = [1,4,7,9]
      curr_key = 0
      for i in range(0, self.text_key_size, 16):
        temp_key = self.rotate_key_right((text_key >> i) & 0xFFFF, shift[(i//16)%4], 16)
        curr_key += (self.permutate_inv(temp_key) << i)
      text_key = curr_key
      curr_key = 0
      for i in range(0, self.text_key_size, 4):
        curr_key += ((self.sbox_inv[(text_key >> i) & 0xF]) << i)
      text_key = curr_key ^ self.round_key((self.round+1)-x)
    return text_key
  
  def decrypt_from_hex(self,text):
    self.text_key_size = len(text)*4
    return self.__decrypt(self.hex_string_to_int(text))

  def decrypt_to_hex(self,text):
    return self.int_to_hex_string(self.decrypt_from_hex(text)).zfill(self.text_key_size//4)

  def decrypt_to_bin(self,text):
    return bin(self.decrypt_from_hex(text)).zfill(self.text_key_size)
  
  def decrypt_from_int(self,text):
    self.text_key_size = (text).bit_length()
    return self.__decrypt(text)
  
  def round_key(self,round):
    shift_size = (13*round) % 128
    curr_key = ((self.master_key << shift_size)|(self.master_key >> (self.master_key_size - shift_size))) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    curr_key = curr_key & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    curr_set = int((self.master_key_size-128) / 64) % 4
    if curr_set == 0:
      sub_key = curr_key & 0xFFFF
    elif curr_set == 1:
      sub_key = curr_key & 0xFFFFFFFF
    elif curr_set == 2:
      sub_key = curr_key & 0xFFFFFFFFFFFF
    elif curr_set == 3:
      sub_key = curr_key & 0xFFFFFFFFFFFFFFFF
    set_bits = curr_set * 16
    first_key  = (sub_key >> set_bits) & 0xF
    second_key = (sub_key >> set_bits+4) & 0xF
    third_key  = (sub_key >> set_bits+8) & 0xF
    fourth_key = (sub_key >> set_bits+12) & 0xF

    first_key = self.sbox[first_key]
    second_key = self.sbox[second_key] 
    third_key = self.sbox[third_key]
    fourth_key = self.sbox[fourth_key]

    fourth_key = (fourth_key << 4) | third_key
    fourth_key = (fourth_key << 4) | second_key
    fourth_key = (fourth_key << 4) | first_key
    sub_key = (sub_key >> 16) << 16 | fourth_key

    if curr_set == 1:
      sub_key = sub_key << set_bits | (curr_key & 0xFFFF)
    elif curr_set == 2:
      sub_key = sub_key << set_bits | (curr_key & 0xFFFFFFFF)
    elif curr_set == 3:
      sub_key = sub_key << set_bits | (curr_key & 0xFFFFFFFFFFFF)
    return sub_key ^ round

  def hex_string_to_int(self,key):
    return int(key, 16)
  
  def int_to_hex_string(self,key):
    return format(key, 'x')
  
  def permutate(self, key):
    result = 0
    for i in range(0,16):
      result += ((key >> (i)) & 0x01) << self.pbox[i]
    return result
  
  def permutate_inv(self, key):
    result = 0
    for i in range(0, 16):
      result += ((key >> i) & 0x01) << self.pbox_inv[i]
    return result
  
  def rotate_key_left(self, key, shift_size, key_size):
    return ((key << shift_size)|(key >> (key_size - shift_size))) & 0xFFFF
  
  def rotate_key_right(self, key, shift_size, key_size):
    return ((key >> shift_size)|(key << (key_size - shift_size)))  & 0xFFFF
