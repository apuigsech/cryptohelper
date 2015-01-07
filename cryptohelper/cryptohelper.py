#!/usr/bin/env python

# Generic Cryptography code utils used on matasano cryptography challenges (http://cryptopals.com/)
#
# Copyright (c) 2015 - Albert Puigsech Galicia (albert@puigsech.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import math
from Crypto.Cipher import AES

def strxor(a, b):
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])


def cryptoxor(input, key):
	ks = key*((len(input)/len(key))+1)
	return strxor(input, ks)


def encrypt_stream_XOR(pt, key):
	return cryptoxor(pt, key)


def decrypt_stream_XOR(ct, key):
	return cryptoxor(pt, key)


def block_split(data, blocklen):
	return [data[i*blocklen:(i+1)*blocklen] for i in range(int(math.ceil(float(len(data))/blocklen)))]


def block_join(blocks):
	return ''.join(blocks)


def block_pad_PKCS7(block, blocklen):
	padlen = blocklen-len(block)
	return block + chr(padlen)*padlen


def data_pad_PKCS7(data, blocklen):
	blocks = block_split(data, blocklen)
	if len(blocks[-1]) < blocklen:
		blocks[-1] = block_add_padding(blocks[-1], blocklen)
	else:
		blocks.append(block_add_padding('', blocklen))
	return block_join(blocks)


def encrypt_block_AES(pt, key):
	aes = AES.new(key, AES.MODE_ECB)
	return aes.encrypt(pt)


def decrypt_block_AES(ct, key):
	aes = AES.new(key, AES.MODE_ECB)
	return aes.decrypt(ct)


def encrypt_block_ECB(pt, blocklen, key, prf):
	blocks_pt = block_split(pt, blocklen)
	blocks_ct = [None] * len(blocks_pt)
	for i in range(len(blocks_pt)):
		blocks_ct[i] = prf(blocks_pt[i], key)
	return block_join(blocks_ct)


def decrypt_block_ECB(ct, blocklen, key, prf):
	return encrypt_block_ECB(ct, blocklen, key, prf)


def encrypt_block_CBC(pt, blocklen, iv, key, prf):
	blocks_pt = block_split(pt, blocklen)
	blocks_ct = [None] * len(blocks_pt)
	prev_block = iv
	for i in range(len(blocks_pt)):
		blocks_ct[i] = prf(strxor(blocks_pt[i], prev_block), key)
		prev_block = blocks_ct[i]
	return block_join(blocks_ct)


def decrypt_block_CBC(ct, blocklen, iv, key, prf):
	blocks_ct = block_split(ct, blocklen)
	blocks_pt = [None] * len(blocks_ct)
	prev_block = iv
	for i in range(len(blocks_pt)):
		blocks_pt[i] = strxor(prf(blocks_ct[i], key), prev_block)
		prev_block = blocks_ct[i]
	return block_join(blocks_pt)



def hamming_distance(s1, s2):
	dist = 0
	if len(s1) == len(s2):
		for i in range(0, len(s1)):
			if s1[i] != s2[i]:
				dist = dist+1
	return dist


def bit_hamming_distance(s1, s2):
	b1 = ''.join(format(ord(x), '08b') for x in s1)
	b2 = ''.join(format(ord(x), '08b') for x in s2)
	return hamming_distance(b1,b2)


freq_eng = {
	'a':8.167, 'b':1.492, 'c':2.782,'d':4.253,'e':12.702,'f':2.228,'g':2.015,'h':6.094,
	'i':6.966,'j':0.153,'k':0.772,'l':4.025,'m':2.406,'n':6.749,'o':7.507,'p':1.929,
	'q':0.095,'r':5.987,'s':6.327,'t':9.056,'u':2.758,'v':0.978,'w':2.360,'x':0.150,
	'y':1.974,'z':0.074
}


def text_frequency_score(text, freq, average=True):
	score = 0.0
	for ch in text:
		if freq.has_key(ch):
			score += 10 + freq[ch]
	if average == True:
		score = score/len(text)
	return score


def xor_statistical_candidates(ct, freq=freq_eng):
	candidates = []
	for key in range(0,255):
		pt = strxor(ct,chr(key)*len(ct))
		candidates.append([key, pt, text_frequency_score(pt, freq)])
	return sorted(candidates, key=lambda x: x[2], reverse=True)


def xor_keylen_score(ct, keylen, samples):
	chunks = [ct[i*keylen:(i+1)*keylen] for i in range(samples)]
	global_distance = 0
	for c1 in chunks:
		for c2 in chunks[chunks.index(c1)+1:]:
			global_distance = global_distance + float(bit_hamming_distance(c1, c2))/keylen
	return global_distance/(samples*(samples-1)/2)


def xor_statistical_keylens(ct, maxlen):
	scores = []
	for keylen in range(1, maxlen):
		score = xor_keylen_score(ct, keylen, 7)
		scores.append([keylen,score])
	return sorted(scores, key=lambda x: x[1])


def unique_blocks_ratio(text, blocklen, numblocks=None):
	if (numblocks == None):
		numblocks = len(text)/blocklen

	unique_chunks = set([text[i*blocklen:(i+1)*blocklen] for i in range(numblocks)])

	return float(len(unique_chunks))/numblocks