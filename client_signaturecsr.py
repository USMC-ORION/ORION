#!/usr/bin/python

'''
File: client_signaturecsr.py
Description: Allows client to send CSR to EMAIL CA
Last modified: 6/29/2020
Modified by: Jack Chang
'''

import socket
import codecs
import sys
import os
import threading
import time

def send_csr():   
    ip_address = str(sys.argv[1]) 
    port = int(sys.argv[2]) 
    fileName = str(sys.argv[3])
    CN = str(sys.argv[4])

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

        # Initiate session communication with server
        fileConnection.sendall('Hello\n') 
        serverReply = fileConnection.recv(1024)
        print('Server Response: ' + serverReply)

        # Inform csr about pending csr file transfer
        fileConnection.sendall(fileName + '\n') 
        serverReply = fileConnection.recv(1024)
        print('Server Response: ' + serverReply)

        # Send csr file
        requestedFile = open(fileName, 'rb') # read binary
        fileInfo = requestedFile.read(8192) 
        print('Preparing to transfer: ' + fileName)
        while fileInfo:
            fileConnection.send(fileInfo)
            fileInfo = requestedFile.read(8192)
        requestedFile.close()
        print('Completed transfer: ' + fileName)     

        # Check if CA received CSR
        serverReply = fileConnection.recv(1024)
        print('Server Response: ' + serverReply)   

        # Let CA know ready for digital signature certificate
        print('Receiving Digital Signature Certificate from ORION EMAIL CA...\n')
        serverReply = fileConnection.recv(1024)
        fileSize = int(serverReply.split(' ')[1])
        fileName = serverReply.split(' ')[0]
        print('Server Response: ' + serverReply)
        fileConnection.sendall('OK\n') 
        p12 = fileName

        deviceCert = CN + '.signature.crt'
        # Receive the p12 containing the signed digital signature public certificate
        # PKCS12 is binary format so need to encode as utf-8
        with codecs.open(p12, 'wb') as cert_file:
            while True:
                fileBuffer = fileConnection.recv(fileSize)
                if not fileBuffer:
                    break
                cert_file.write(fileBuffer)
        cert_file.close()
        print('Received: ' + p12 + ' of size: ' + str(fileSize) + ' bytes\n')
    
        # Extract digital signature certificate from p12
        thread = threading.Thread(target = os.system('openssl pkcs12 -in ' + p12 + ' -out ' + deviceCert + ' -nokeys -password pass:password'))
	thread.start()
	thread.join()
        print('Digital Signature Certificate extracted from P12\n')         

        print('Connection with EMAIL CA closed...\n')
        fileConnection.close()

    except socket.error as e:
        print(str(e))
        print('\nExiting...\n')
        exit()

if __name__ == '__main__':
    send_csr()
