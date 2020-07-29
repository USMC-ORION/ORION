#!/usr/bin/python

'''
File: connectemailCA.py
Description: Allows client to connect to SCEP EMAIL CA
Last modified: 6/29/2020
Modified by: Jack Chang
'''

import socket
import codecs
import sys
import os
import threading
import time

def connection():   
    ip_address = str(sys.argv[1]) 
    port = int(sys.argv[2]) 
    caHash = str(sys.argv[3])

    fileConnection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        while True:
            try:
                print('Establishing connection with ORION EMAIL CA...')
                fileConnection.connect((ip_address, port))
                break
            except socket.error:
                print('Connection failed: retrying..')
                time.sleep(1)
                pass

        # Initiate session communication with CA
        fileConnection.sendall('Hello\n') 
        serverReply = fileConnection.recv(1024)
        print('Server Response: ' + serverReply)

	# Send GETCACERT request
        print('Sending GETACERT request to EMAIL CA...\n')
        fileConnection.sendall('GETCACERT\n') 
        serverReply = fileConnection.recv(1024)
        fileSize = int(serverReply.split(' ')[1])
        fileName = serverReply.split(' ')[0]
        print('Server Response: ' + serverReply)
        fileConnection.sendall('OK\n') 
        p12 = fileName

        # Receive the p12 containing CA public certificate
        with codecs.open(p12, 'wb') as p12_file:
            while True:
                fileBuffer = fileConnection.recv(fileSize)
                if not fileBuffer:
                    break
                p12_file.write(fileBuffer)
        p12_file.close()
        print('Received: ' + p12 + ' of size: ' + str(fileSize) + ' bytes\n')
    
        # Extract CA public certificate from p12
        caCert = 'EMAILCA.crt'
        thread = threading.Thread(target = os.system('openssl pkcs12 -in ' + p12 + ' -out ' + caCert + ' -nokeys -password pass:password'))
	thread.start()
	thread.join()

        # Compare hash of CA certificate to hash in SCEP instruction
        thread = threading.Thread(target = os.system('openssl x509 -noout -hash -in ' + caCert + ' > caCert_hash.txt'))
	thread.start()
	thread.join()
        with open('caCert_hash.txt', 'r') as hash_info:
            caCert_hash = hash_info.read()
        hash_info.close()      

        # Clean up the hash string
        caCert_hash = caCert_hash.strip()
        print('hash of ' + caCert + ': ' + caCert_hash)

        if caCert_hash == caHash:
            print('EMAIL CA public certificate hash successfully verified\n')
        else:
            print('EMAIL CA public certificate invalid\n')
            print('Connection with EMAIL CA closed...\n')
            exit()

        print('Connection with EMAIL CA closed...\n')
        fileConnection.close()

    except socket.error as e:
        print(str(e))
        print('\nExiting...\n')
        exit()

if __name__ == '__main__':
    connection()
