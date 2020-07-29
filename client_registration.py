#!/usr/bin/python

'''
File: client_registration.py
Description: Main program for client-side Orion Registration App
Last modified: 6/29/2020
Modified by: Jack Chang
'''

from OpenSSL import crypto, SSL
import random
import string
import socket
import os
import codecs
import time
import threading

# Global variables
connection = 0

def welcome_script():
    print('\n******************************')
    print('*** ORION Registration App ***')
    print('******************************\n')

def appChoices():
    print('~~~ Main Menu ~~~~\
            \n[1] Expedited Device Credentialing\
            \n[2] Exit App\n')

    while True:
        selection = raw_input('Select an option [ ]: ')
        if selection not in {'1', '2'}:
            print('*** Error: Please enter a valid integer option ***\n')
        else:
            break
    
    # Expedited Device Registration
    if selection == '1':
        print('Requesting expedited device credentialing...')
        connection.sendall('expedited_device\n')
        server_reply = connection.recv(1024)
        print('Server Response: ' + server_reply)
        generate_deviceCert()
    
    # Exit app
    elif selection == '2':
        print('\nExiting ORION Registration App...\n')
        connection.sendall('Bye\n') 
        # Close session communication with server
        server_reply = connection.recv(1024)
        print('Server Response: ' + server_reply)
        exit()

def generate_serialNumber(serial_length = 6):
    return ''.join((random.choice(string.digits) for i in range(serial_length)))

def client_fullName():
    while True:
        fullName = raw_input('Enter your full name i.e., Lewis Burwell Puller: \n>Full Name: ')
        if len(fullName.split(' ')) < 2 or len(fullName.split(' ')) > 3:
            print('***Error: Not a full name***\n ')
            client_fullName()
        else:
            for word in fullName.split(' '):
                if not word.isalpha():
                    print('***Error: Name can only be alphabetic characters\n***')
                    client_fullName()
        return fullName

def client_edipi():
    while True:
        edipi = raw_input('Enter your EDIPI: \n>EDIPI: ') 
        if edipi.isdigit() and len(edipi) == 10:
            return edipi    
        else:
            print('***Error: Not a valid EDIPI\n***')  
            client_edipi()

def biometric_verification():
    # Simulates biometric check by using password in place of biometric modality
    biometric_input = raw_input('For security, ORION needs to verify your identity: \n>Fingerprint: ')
    return biometric_input

def generate_deviceCert():
    # Prompt user for basic registration information
    fullName = client_fullName()
    email = raw_input('Enter your DoD e-mail address i.e., lewis.puller@usmc.mil: \n>E-mail: ')
    edipi = client_edipi()
    device_serial = raw_input('Enter your device serial number: \n>Device S/N: ')   
    # Initial biometric verification
    fingerprint = biometric_verification()
    
    # Timer
    start = time.time()

    # Populate certificate fields
    if len(fullName.split(' ')) == 3: # middlename included
        firstName = fullName.split(' ')[0].upper()
        middleName = fullName.split(' ')[1].upper()
        lastName = fullName.split(' ')[2].upper()
        CN= lastName + '.' + firstName + '.' + middleName + '.' + str(edipi)
    else: # No middlename
        firstName = fullName.split(' ')[0].upper()
        lastName = fullName.split(' ')[1].upper()
        CN= lastName + '.' + firstName + '.' + str(edipi)

    print('\nSending user and device information')
    connection.sendall(CN + ',' + edipi + ',' + fingerprint + ',' + device_serial + ',' + email + '\n') 
    server_reply = connection.recv(1024)
    print('Server Response: ' + server_reply)

    OU = 'USMC'
    O = 'U.S. Government'
    C = 'US'
    serial_number = int(generate_serialNumber(6))
    notBefore = 0
    notAfter=10*365*24*60*60
    privateKey = CN + '.key'
    pubCert = CN + '.crt'

    # Generate 2048-bit RSA private key
    print('Generating 2048-bit RSA private key\n')
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Generate self-signed X.509 public certificate
    # Check certificate: openssl x509 -in selfsigned.crt -noout -text
    # Check private key: openssl rsa -in private.key -check
    print('Generating self-signed X.509 public certificate\n')
    x509 = crypto.X509()
    x509.get_subject().emailAddress = email
    x509.get_subject().OU = OU
    x509.get_subject().CN = CN
    x509.get_subject().O = O
    x509.get_subject().C = C
    x509.set_serial_number(serial_number)
    x509.gmtime_adj_notBefore(notBefore)
    x509.gmtime_adj_notAfter(notAfter)
    x509.set_issuer(x509.get_subject())
    x509.set_pubkey(key)
    x509.sign(key, 'sha256')
    with open(pubCert, 'wt') as pubCert_file:
        pubCert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, x509).decode('utf-8'))
    with open(privateKey, 'wt') as privateKey_file:
        privateKey_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8'))
    
    # Prepare self-signed public certificate for export
    print('Creating p12 containg self-signed public certificate\n')
    self_p12 = generate_p12(CN, pubCert)

    # Sending p12 containing self-signed public certificate
    print('Checking if server is ready for file transfer...')
    connection.sendall(self_p12 + '\n') 
    server_reply = connection.recv(1024)
    print('Server Response: ' + server_reply)

    # Server is ready for the file transfer, send p12
    thread = threading.Thread(target = os.system('python ./send_p7.py ' + self_p12))
    thread.start()
    thread.join()
 
    # Confirm server receipt
    connection.sendall('OK\n') 
    server_reply = connection.recv(1024)
    fileSize = int(server_reply.split(' ')[1])
    fileName = server_reply.split(' ')[0]
    print('Server Response: ' + server_reply)
    
    # Server p7 initiation message
    connection.sendall('OK - Send\n')
    
    # Receive server challenge p7
    decryptMsg = 'decrypted.txt'
    thread = threading.Thread(target = os.system('python ./receive_p7.py ' + fileName + ' ' + str(fileSize)))
    thread.start()
    thread.join()

    # Decrypt the p7 to extract the server's challenge password
    thread = threading.Thread(target = os.system('openssl smime -decrypt -inform pem -in ' + fileName + ' -inkey ' + privateKey + ' -out ' + decryptMsg))
    thread.start()
    thread.join()
    print(fileName + ' successfully decrypted with ' + privateKey + '; server challenge stored as ' + decryptMsg + '\n')

    # Create a signed p7 containing the encrypted decrypted challenge
    signedp7 = 'signed.p7'
    thread = threading.Thread(target = os.system('openssl smime -sign -nodetach -in ' + decryptMsg + ' -out ' + signedp7 + ' -outform pem -inkey ' + privateKey + ' -signer ' + pubCert))
    thread.start()
    thread.join()
    print(signedp7 + ' containing ' + decryptMsg + ' successfuly encrypted and signed with ' + privateKey + '\n')

    # Check if server ready for file transfer
    print('Checking if server is ready for file transfer...')
    connection.sendall(signedp7 + '\n') 
    server_reply = connection.recv(1024)
    print('Server Response: ' + server_reply)

    # Send the signed p7
    thread = threading.Thread(target = os.system('python ./send_p7.py ' + signedp7))
    thread.start()
    thread.join()

    # Check if server successfuly received p7
    server_reply = connection.recv(1024)
    print('Server Response: ' + server_reply)
    
    # Signal to receive p7 containing SCEP instructions
    connection.sendall('OK CA\n')
    server_reply = connection.recv(1024)
    fileSize = int(server_reply.split(' ')[1])
    fileName = server_reply.split(' ')[0]
    print('Server Response: ' + server_reply)

    # Server p7 initiation message
    connection.sendall('OK - Send\n')
    
    # Receive the encrypted SCEP p7 from the server
    thread = threading.Thread(target = os.system('python ./receive_p7.py ' + fileName + ' ' + str(fileSize)))
    thread.start()
    thread.join()
    p7 = fileName
    decryptMsg = 'scep.txt'

    # Decrypt the p7 to extract the SCEP instructions
    thread = threading.Thread(target = os.system('openssl smime -decrypt -inform pem -in ' + p7 + ' -inkey ' + privateKey + ' -out ' + decryptMsg))
    thread.start()
    thread.join()
    print(p7 + ' successfully decrypted with ' + privateKey + '; server challenge stored as ' + decryptMsg + '\n')
    
    # Open scep.txt and retrieve SCEP instructions
    with open('scep.txt', 'r') as scep_info:
        info = scep_info.read()
    scep_info.close()       
    CA_ip = info.split()[0]
    CA_port = info.split()[1]
    CAcert_hash = info.split()[2]

    # Connect to SCEP Device CA, request Device CA public certificate, authenticate CA public certificate 
    thread = threading.Thread(target = os.system('python ./connectCA.py ' + CA_ip + ' ' + CA_port + ' ' + CAcert_hash))
    thread.start()
    thread.join()

    # Create CSR using a new private key
    privateKey = CN + '.device.key'
    csr = CN + '.csr'
    thread = threading.Thread(target = os.system('openssl genrsa -out ' + privateKey + ' 2048'))
    thread.start()
    thread.join()
    print('Done.\n')
    print('Generating CA Certificate Signing Request...\n')
    thread = threading.Thread(target = os.system('openssl req -new -key ' + privateKey + ' -out ' + csr + ' -subj "/C=US/OU=USMC/O=U.S.GOVERNMENT/CN=' + CN + '/emailAddress=' + email + '" -addext "keyUsage=digitalSignature"'))
    thread.start()
    thread.join()    
    print('Done.\n')

    # Connect to SCEP CA, send CSR, receive CA signed device certificate
    thread = threading.Thread(target = os.system('python ./client_csr.py ' + CA_ip + ' ' + CA_port + ' ' + csr + ' ' + CN))
    thread.start()
    thread.join()

    # Second server p7 initiation message
    connection.sendall('OK\n') 
    server_reply = connection.recv(1024)
    fileSize = int(server_reply.split(' ')[1])
    fileName = server_reply.split(' ')[0]
    print('Server Response: ' + server_reply)
    connection.sendall('OK - Send\n')
    
    # Receive server challenge p7
    thread = threading.Thread(target = os.system('python ./receive_p7.py ' + fileName + ' ' + str(fileSize)))
    thread.start()
    thread.join()
    decryptMsg = 'decrypted2.txt'

    # Decrypt the p7 to extract the server's challenge password
    privateKey = CN + '.device.key'
    thread = threading.Thread(target = os.system('openssl smime -decrypt -inform pem -in ' + fileName + ' -inkey ' + privateKey + ' -out ' + decryptMsg))
    thread.start()
    thread.join()
    print(fileName + ' successfully decrypted with ' + privateKey + '; server challenge stored as ' + decryptMsg + '\n')      

    # Create a signed p7 containing the encrypted decrypted challenge
    signedp7 = 'signed2.p7'
    pubCert = CN + '.device.crt'
    thread = threading.Thread(target = os.system('openssl smime -sign -nodetach -in ' + decryptMsg + ' -out ' + signedp7 + ' -outform pem -inkey ' + privateKey + ' -signer ' + pubCert))
    thread.start()
    thread.join()
    print(signedp7 + ' containing ' + decryptMsg + ' successfuly encrypted and signed with ' + privateKey + '\n')

    # Check if server ready for file transfer
    print('Checking if server is ready for file transfer...')
    connection.sendall(signedp7 + '\n') 
    server_reply = connection.recv(1024)
    print('Server Response: ' + server_reply)

    # Send the signed p7
    thread = threading.Thread(target = os.system('python ./send_p7.py ' + signedp7))
    thread.start()
    thread.join()

    # Check if server successfuly received p7
    server_reply = connection.recv(1024)
    print('Server Response: ' + server_reply)
    end = time.time()
    elapsedTime = end - start

    # Final biometric verification
    fingerprint = raw_input('Authenticate your identity to complete the process: \n>Fingerprint: ')
    print('\nProcessing.....')
    connection.sendall(fingerprint + '\n')
    server_reply = connection.recv(1024)
    print('Server Response: ' + server_reply)
    print('+++++ ORION Device Enrollment Complete - Total Elapsed Time: ' + str(elapsedTime) + ' Seconds +++++\n')
    print('+++++ Device serial: ' + device_serial + ' is now credentialed to user EDIPI: ' + edipi + '  +++++\n')
    choice = raw_input('Press [Enter] to continue to expedited credentialing\n')
    while True:    
        if choice == '':
            break
        choice = raw_input('Press Enter to continue to expedited credentialing\n')

    # Generate new PIV Auth, Signature, and Encryption Certificate
    generate_credentials(privateKey, CN, email)
        
def generate_credentials(privateKey, CN, email):
    # Initial biometric verification
    fingerprint = biometric_verification()
    start = time.time()
    connection.sendall(fingerprint + '\n')

    # Server authenticates fingerprint
    server_reply = connection.recv(1024)
    print('Server Response: ' + server_reply)

    ############
    # PIV AUTH #    
    ############

    # Signal to receive p7 containing SCEP instructions
    connection.sendall('OK - CA\n')
    server_reply = connection.recv(1024)
    fileSize = int(server_reply.split(' ')[1])
    fileName = server_reply.split(' ')[0]
    print('Server Response: ' + server_reply)

    # Server p7 initiation message
    connection.sendall('OK - Send\n')

    # Receive the encrypted SCEP p7 from the server
    thread = threading.Thread(target = os.system('python ./receive_p7.py ' + fileName + ' ' + str(fileSize)))
    thread.start()
    thread.join()
    p7 = fileName
    decryptMsg = 'scep.txt'

    # Decrypt the p7 to extract the SCEP instructions using device private key
    thread = threading.Thread(target = os.system('openssl smime -decrypt -inform pem -in ' + p7 + ' -inkey ' + privateKey + ' -out ' + decryptMsg))
    thread.start()
    thread.join()
    print(p7 + ' successfully decrypted with ' + privateKey + '; server challenge stored as ' + decryptMsg + '\n')

    # Open scep.txt and retrieve SCEP instructions
    with open('scep.txt', 'r') as scep_info:
        info = scep_info.read()
    scep_info.close()       
    CA_ip = info.split()[0]
    CA_port = info.split()[1]
    CAcert_hash = info.split()[2]

    # Connect to SCEP ID CA, request ID CA public certificate, authenticate CA public certificate 
    thread = threading.Thread(target = os.system('python ./connectIDCA.py ' + CA_ip + ' ' + CA_port + ' ' + CAcert_hash))
    thread.start()
    thread.join()

    # Create PIVAuth CSR using a new private key
    pivKey = CN + '.PIV.key'
    csr = CN + '.piv.csr'
    thread = threading.Thread(target = os.system('openssl genrsa -out ' + pivKey + ' 2048'))
    thread.start()
    thread.join()
    print('Done.\n')
    print('Generating CA Certificate Signing Request...\n')
    thread = threading.Thread(target = os.system('openssl req -new -key ' + pivKey + ' -out ' + csr + ' -subj "/C=US/OU=USMC/O=U.S.GOVERNMENT/CN=' + CN + '/emailAddress=' + email + '" -addext "keyUsage=digitalSignature"'))
    thread.start()
    thread.join()
    print('Done.\n')

    # Connect to SCEP CA, send CSR, receive CA signed PIV Auth certificate
    thread = threading.Thread(target = os.system('python ./client_pivcsr.py ' + CA_ip + ' ' + CA_port + ' ' + csr + ' ' + CN))
    thread.start()
    thread.join()
    print('+++++ PIV Authentication Credential Received +++++\n')

    #############
    # Signature #    
    #############

    # Signal to receive p7 containing SCEP instructions
    connection.sendall('OK - CA\n')
    server_reply = connection.recv(1024)
    fileSize = int(server_reply.split(' ')[1])
    fileName = server_reply.split(' ')[0]
    print('Server Response: ' + server_reply)

    # Server p7 initiation message
    connection.sendall('OK - Send\n')

    # Receive the encrypted SCEP p7 from the server
    thread = threading.Thread(target = os.system('python ./receive_p7.py ' + fileName + ' ' + str(fileSize)))
    thread.start()
    thread.join()
    p7 = fileName
    decryptMsg = 'scep.txt'

    # Decrypt the p7 to extract the SCEP instructions using device private key
    thread = threading.Thread(target = os.system('openssl smime -decrypt -inform pem -in ' + p7 + ' -inkey ' + privateKey + ' -out ' + decryptMsg))
    thread.start()
    thread.join()    
    print(p7 + ' successfully decrypted with ' + privateKey + '; server challenge stored as ' + decryptMsg + '\n')

    # Open scep.txt and retrieve SCEP instructions
    with open('scep.txt', 'r') as scep_info:
        info = scep_info.read()
    scep_info.close()       
    CA_ip = info.split()[0]
    CA_port = info.split()[1]
    CAcert_hash = info.split()[2]

    # Connect to SCEP Email CA, request Email CA public certificate, authenticate CA public certificate 
    thread = threading.Thread(target = os.system('python ./connectemailCA.py ' + CA_ip + ' ' + CA_port + ' ' + CAcert_hash))
    thread.start()
    thread.join()    

    # Create Digital Signature CSR using a new private key
    signKey = CN + '.signature.key'
    csr = CN + '.signature.csr'
    thread = threading.Thread(target = os.system('openssl genrsa -out ' + signKey + ' 2048'))
    thread.start()
    thread.join() 
    print('Done.\n')
    print('Generating CA Certificate Signing Request...\n')
    thread = threading.Thread(target = os.system('openssl req -new -key ' + signKey + ' -out ' + csr + ' -subj "/C=US/OU=USMC/O=U.S.GOVERNMENT/CN=' + CN + '/emailAddress=' + email + '" -addext "keyUsage=digitalSignature"'))
    thread.start()
    thread.join()    
    print('Done.\n')

    # Connect to SCEP CA, send CSR, receive CA signed signature certificate
    thread = threading.Thread(target = os.system('python ./client_signaturecsr.py ' + CA_ip + ' ' + CA_port + ' ' + csr + ' ' + CN))
    thread.start()
    thread.join()    
    print('+++++ Digital Signature Credential Received +++++\n')

    ##############
    # Encryption #    
    ##############
    
    # Encryption certificate is different because key pair is generated by the ORA
    # Signal to receive p7 containing SCEP instructions
    connection.sendall('OK - CA\n')
    server_reply = connection.recv(1024)
    fileSize = int(server_reply.split(' ')[1])
    fileName = server_reply.split(' ')[0]
    print('Server Response: ' + server_reply)

    # Server p7 initiation message
    connection.sendall('OK - Send\n')

    # Receive the encrypted SCEP p7 from the server
    thread = threading.Thread(target = os.system('python ./receive_p7.py ' + fileName + ' ' + str(fileSize)))
    thread.start()
    thread.join()
    p7 = fileName
    decryptMsg = 'scep.txt'

    # Decrypt the p7 to extract the SCEP instructions using device private key
    thread = threading.Thread(target = os.system('openssl smime -decrypt -inform pem -in ' + p7 + ' -inkey ' + privateKey + ' -out ' + decryptMsg))
    thread.start()
    thread.join()
    print(p7 + ' successfully decrypted with ' + privateKey + '; server challenge stored as ' + decryptMsg + '\n')

    # Open scep.txt and retrieve SCEP instructions
    with open('scep.txt', 'r') as scep_info:
        info = scep_info.read()
    scep_info.close()       
    CA_ip = info.split()[0]
    CA_port = info.split()[1]
    CAcert_hash = info.split()[2]

    # Connect to SCEP Email CA, request Email CA public certificate, authenticate CA public certificate 
    thread = threading.Thread(target = os.system('python ./connectemailCA.py ' + CA_ip + ' ' + CA_port + ' ' + CAcert_hash))
    thread.start()
    thread.join()

    print('ORION Registration App is generating new key pair and Encryption CSR...\n')

    # Receive encrypted p12 with encryption certificate from ORA
    server_reply = connection.recv(1024)
    print('Server Response: ' + server_reply)
    connection.sendall('OK - Send\n')
    thread = threading.Thread(target = os.system('python ./get_encryptionCert.py ' + CN))
    thread.start()
    thread.join()

    # Receive p7 containing encrypted p12 with encryption private key from ORA
    connection.sendall('OK - Server\n')
    server_reply = connection.recv(1024)
    fileSize = int(server_reply.split(' ')[1])
    fileName = server_reply.split(' ')[0]
    print('Server Response: ' + server_reply)

    # Server p7 initiation message
    connection.sendall('OK - Send\n')
    thread = threading.Thread(target = os.system('python ./receive_p7.py ' + fileName + ' ' + str(fileSize)))
    thread.start()
    thread.join()
    p7 = fileName

    # Decrypt the p7 to extract the contents
    encryptedKey = 'encrypted.key'
    thread = threading.Thread(target = os.system('openssl smime -decrypt -inform pem -in ' + p7 + ' -inkey ' + privateKey + ' -out ' + encryptedKey))
    thread.start()
    thread.join()
    print(p7 + ' successfully decrypted with ' + privateKey + '; stored as ' + encryptedKey + '\n')

    # Decrypt the encrypted private key
    encryptionKey = CN + '.encryption.key'
    thread = threading.Thread(target = os.system('openssl rsa -in ' + encryptedKey + ' -out ' + encryptionKey + ' -passin pass:password'))
    thread.start()
    thread.join()
    print(encryptedKey + ' successfully decrypted: ' + encryptionKey + '\n')

    print('+++++ Encryption Key/Credential Received +++++\n')
    end = time.time()
    elapsedTime = end - start
    print('*** Subscriber Credentialing Completed - Total Elapsed Time: ' + str(elapsedTime) + ' Seconds ***')
    
def generate_p12(CN, pubCert):
    # PKCS #12 filename to save as
    p12_file = CN + '.pfx'
    # Open certificate and read certificate info
    with open(pubCert, 'rb') as publicCert:
        pemText = publicCert.read()
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, pemText)
    # Object representing PKCS #12
    p12 = crypto.PKCS12()
    # Set certificate in PKCS #12 structure
    p12.set_certificate(cert)
    # Dump PKCS #12 as string, set import password as 'password'
    p12Text = p12.export('password')
    # Write as binary to PKCS #12
    with open(p12_file, 'wb') as p12File:
        p12File.write(p12Text)
    return p12_file
    # Check PKCS #12 file with openssl pkcs12 -info -in fileName.pfx

def connect_to_orion():
    # Connect to ORION Registration App server
    global connection
    ip_address = '10.0.0.3'
    port = 9999
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.connect((ip_address, port))
        print('\nInitiating session with ORION Registration Server...')
        # Initiate session communication with server
        connection.sendall('Hello\n') 
        server_reply = connection.recv(1024)
        print('Server Response: ' + server_reply)
    except socket.error as e:
        print(str(e))
        print('\nExiting...\n')
        exit()

if __name__ == '__main__':
    connect_to_orion()
    welcome_script()
    appChoices()
