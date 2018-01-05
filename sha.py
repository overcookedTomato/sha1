#!/usr/bin/env python3.6
#encoding=utf-8





"""TODO : handle any file type, make tests """


import struct
import io
import os, sys


def bin_return(dec):
    return(str(format(dec,'b')))

def bin_8bit(dec):
    return(str(format(dec,'08b')))

def bin_32bit(dec):
    return(str(format(dec,'032b')))

def hex_return(dec):
    return(str(format(dec,'x')))

def dec_return_bin(bin_string):
    return(int(bin_string,2))

def dec_return_hex(hex_string):
    return(int(hex_string,16))   


#returns 64bits representation of number passed. Useful for padding message length for example

def bin_64bit(dec):
	return(str(format(dec,'064b')))


#list to string ?

def l_s(bit_list):
	bit_string=''
	for i in range(len(bit_list)):
		bit_string+=bit_list[i]
	return(bit_string)


#same padding as in MD5: First add a one, then as many zeros as necessary to make it 64 bits short of a multiple of 512, and finally a 64 bits representation of the length of the message before padding

def message_pad(bit_list):
	pad_one = bit_list + '1'    
	pad_len = len(pad_one)     
	k=0
	while ((pad_len+k)-448)%512 != 0:
		k+=1
	back_append_0 = '0'*k
	back_append_1 = bin_64bit(len(bit_list))
	return(pad_one+back_append_0+back_append_1) 


# if given "test" returns "01110100011001010111001101110100"

def message_bit_return(string_input):
	bit_list=[]
	for i in range(len(string_input)):
		bit_list.append(bin_8bit(ord(string_input[i])))
	return(l_s(bit_list))  



def message_pre_pro(input_string):
	bit_main = message_bit_return(input_string)
	return(message_pad(bit_main)) 


#decimal to binary

def dec_return_bin(bin_string):
	return(int(bin_string,2))


#decimal to hex

def dec_return_hex(hex_string):
	return(int(hex_string,16))



def left_rotate(n, b):
	"""Left rotate a 32-bit integer n by b bits."""
	return ((n << b) | (n >> (32 - b))) & 0xffffffff






# """Process a 64 bytes chunk of data and return the new digest variables."""

def process_chunk(chunk, h0, h1, h2, h3, h4):

	assert len(chunk) == 64

	#The main loop has four rounds of 20 operations each. Each operation performs a non-linear function on three of theses 5 variables and then does shifting and adding similar to MD5 

	a = h0
	b = h1
	c = h2
	d = h3
	e = h4


	#The message block is transformed from 16 32-bit words (M0 to M15) to 80 32-bit words (W0 to W79) using the following algorithm:

	#Wt = Mt for t=0 to 15
	#Wt = (W(t-3)⊕W(t-8)⊕W(t-14)⊕W(t-16) <<< 1, for t=16 to 79

	#(with <<< = linear shift
	#as an interesting aside, the original SHA specification did not have the left circular shift. The change "corrects a technical flaw that made the standard less secure that had been thought" (TODO:source). 
	#The NSA has refused to elaborate on the exact nature of the flaw)

	w = [0] * 80

	  # Break chunk into sixteen 4-byte big-endian words w[i]
	for i in range(16):
		w[i] = struct.unpack(b'>I', chunk[i*4:i*4 + 4])[0]
		#TODO : la même chose sans utiliser unpack ?

	  # Extend the sixteen 4-byte words into eighty 4-byte words
	for i in range(16, 80):
		
		w[i] = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
		

	#SHA's set of non-linear functions is :

	#Ft(X,Y,Z) = (X∧Y)∨((¬X)∧Z) for t=0 to 19
	#Ft(X,Y,Z) = X⊕Y⊕Z for t=20 to 39
	#Ft(X,Y,Z) = (X∧Y)∨(X∧Z)∨(Y∧Z) for t=40 to 59
	#Ft(X,Y,Z) = X⊕Y⊕Z for t=60 to 39

	# (with ⊕ = XOR, ∧ = AND, ∨ = OR and ¬ = two's complement)





	#Four constants are used in the algorithm :

	#Kt = 0x5A827999 for t=0 to 19
	#Kt = 0x6ED9EBA1 ...
	#Kt = 0x8F1BBCDC
	#Kt = 0xCA62C1D6

	#(If you wonder where those numbers came from: 0x5A827999 = 2^(1/2)/4, 0x6ED9EBA1 = 3^(1/2)/4, 0x8F1BBCDC = 5^(1/2)/4 and 0xCA62C1D6 = 10^(1/2)/4; all times 2^32)



	for i in range(80):
		if 0 <= i <= 19:
		   f = d ^ (b & (c ^ d))
		   k = 0x5A827999
		elif 20 <= i <= 39:
		   f = b ^ c ^ d
		   k = 0x6ED9EBA1
		elif 40 <= i <= 59:
		   f = (b & c) | (b & d) | (c & d) 
		   k = 0x8F1BBCDC
		elif 60 <= i <= 79:
		   f = b ^ c ^ d
		   k = 0xCA62C1D6


	#If t is the operation number  (from 0 to 79), Wt represents the tth sub-block of the expanded message , and <<<s represents a left circular shift of s bits, then the main loop looks like:

	#For t = 0 to 79
	# temp = (a<<<5) + Ft(b,c,d) + e + Wt + Kt
	# e = d
	# d = c
	# c = b <<< 30
	# b = a
	# a = temp


		a, b, c, d, e = ((left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, 
							a, left_rotate(b, 30), c, d)


	#After all of this, a,b,c,d and e are added to A, B, C, D and E respectively, and the algorithm continues with the next block of data. The final output is the concatenation of A,B,C,D and E:


	# Add this chunk's hash to result so far
	h0 = (h0 + a) & 0xffffffff
	h1 = (h1 + b) & 0xffffffff 
	h2 = (h2 + c) & 0xffffffff
	h3 = (h3 + d) & 0xffffffff
	h4 = (h4 + e) & 0xffffffff

	return h0, h1, h2, h3, h4




def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])








if len(sys.argv) >= 1:

	#First of all we need to pad this message :
	message_as_bitstring = message_pre_pro(sys.argv[1])
else:
	print("you need to pass the message to hash as a parameter")
	#TODO: raise exception


message = bitstring_to_bytes(message_as_bitstring)


#The main loop of the algorithm begins. It proccesses the message 512 bits at a time and continues for as many 512-bit blocks as are in the message  :

#So we want to get rid of a chunk from our message once it has already been proccessed (TODO: explain properly), we use the "read" function from the io  package for that

if isinstance(message, (bytes, bytearray)):
            unprocessed_data = io.BytesIO(message)
            
            

if len(message)%64 == 0:  #just in case there is a padding error or whatever
	nb_of_chunks = len(message)/64

	#First the five variables are copied into different variables : a gets 0x67452301, b gets 0xEFCDAB89... (in the first round only) TODO: explain what are these variables, some kind of IV
	digest_values = process_chunk(unprocessed_data.read(64), 0x67452301 , 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
          

	for i in range(nb_of_chunks-1):
		digest_values = process_chunk(unprocessed_data.read(64), digest_values[0], digest_values[1], digest_values[2], digest_values[3], digest_values[4])

else:
	print("the message isn't padded properly")
	#TODO: apprendre à utiliser exceptions correctement	



#Let's print the digest as an hex string :

digest = '%08x%08x%08x%08x%08x' % digest_values

print(digest)





			
			