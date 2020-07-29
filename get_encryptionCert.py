#!/usr/bin/python

'''
File: get_encryptionCert.py
Description: Allows client to receive encryption certificate
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
    CN = str(sys.argv[1]) 
    ip_address = '10.0.0.3'
    port = 8888

    fileConnection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        while True:
            try:
                print('Establishing file connection with ORION Registration App...')
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

	# Send encryption certificate request
        print('Sending Encryption Certificate request\n')
        fileConnection.sendall('Send Encryption Cert\n') 
        serverReply = fileConnection.recv(1024)
        fileSize = int(serverReply.split(' ')[1])
        fileName = serverReply.split(' ')[0]
        print('Server Response: ' + serverReply)
        fileConnection.sendall('OK\n') 
        p12 = fileName

        # Receive the p12 containing encryption certificate
        with codecs.open(p12, 'wb') as p12_file:
            while True:
                fileBuffer = fileConnection.recv(fileSize)
                if not fileBuffer:
                    break
                p12_file.write(fileBuffer)
        p12_file.close()
        print('Received: ' + p12 + ' of size: ' + str(fileSize) + ' bytes\n')
    
        # Extract encryption certificate from p12
        encryptionCert = CN + '.encryption.crt'
        thread = threading.Thread(target = os.system('openssl pkcs12 -in ' + p12 + ' -out ' + encryptionCert + ' -nokeys -password pass:password'))
	thread.start()
	thread.join()
	print('Encryption Certificate received: ' + encryptionCert)

        print('Closing file connection...\n')
        fileConnection.close()

    except socket.error as e:
        print(str(e))
        print('\nExiting...\n')
        exit()

if __name__ == '__main__':
    connection()
