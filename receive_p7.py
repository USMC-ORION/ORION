#!/usr/bin/python

'''
File: receive_p7.py
Description: Allows client to receive server p7
Last modified: 6/29/2020
Modified by: Jack Chang
'''

import socket
import codecs
import sys
import time

def receive_p7():   
    fileName= str(sys.argv[1]) 
    fileSize = int(sys.argv[2]) 
    ip_address = '10.0.0.3'
    port = 8888
    fileConnection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        while True:
            try:
                print('Establishing new file stream connection with the server...')
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
        p7 = fileName
        
        fileConnection.sendall('OK\n')        

        # Receive the p7 file
        with codecs.open(p7, 'wb', encoding='utf-8') as p7_file:
            while True:
                fileBuffer = fileConnection.recv(fileSize)
                if not fileBuffer:
                    break
                p7_file.write(fileBuffer)
        p7_file.close()
        print('Received: ' + fileName + ' of size: ' + str(fileSize) + ' bytes\n')
        print('File stream with the server closed...\n')
        fileConnection.close()

    except socket.error as e:
        print(str(e))
        print('\nExiting...\n')
        exit()

if __name__ == '__main__':
    receive_p7()
