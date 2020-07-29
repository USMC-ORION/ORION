#!/usr/bin/python

'''
File: send_p7.py
Description: Allows client to send p7 to server
Last modified: 6/29/2020
Modified by: Jack Chang
'''

import socket
import codecs
import sys
import time

def sendp7():   
    fileName = str(sys.argv[1]) 

    fileConnection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip_address = '10.0.0.3'
    port = 8888
    try:
        while True:
            try:
                print('Establishing connection with ORION DEVICE CA...')
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

        # Send p7
        requestedFile = open(fileName, 'rb') # read binary
        fileInfo = requestedFile.read(8192) 
        print('Preparing to transfer: ' + fileName)
        while fileInfo:
            fileConnection.send(fileInfo)
            fileInfo = requestedFile.read(8192)
        requestedFile.close()
        print('Completed transfer: ' + fileName)     
        print('Connection with DEVICE CA closed...\n')
        fileConnection.close()

    except socket.error as e:
        print(str(e))
        print('\nExiting...\n')
        exit()

if __name__ == '__main__':
    sendp7()
