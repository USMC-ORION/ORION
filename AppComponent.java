/*
 * Copyright 2020-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
File: AppComponent.java
Description: Main program for server-side Orion Registration App
Last modified: 6/29/2020
Modified by: Jack Chang
*/

package org.orion.app;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.InetSocketAddress;
import java.util.HashMap;

@Component(immediate = true)
public class AppComponent 
{

    private final Logger log = LoggerFactory.getLogger(getClass());

    public void orion_server() 
    {
        String clientReply; // Rx from client
        String clientChallenge; // Tx to client
        
        try 
        {
            // Create server socket
            ServerSocket new_socket = new ServerSocket();
            SocketAddress ora_server = new InetSocketAddress("10.0.0.3", 9999);
	    
            // Bind server socket
            new_socket.bind(ora_server);             
            log.info("***Server listening on port 9999***");

            boolean running = true;
            while (running) 
            {                
                // Accept client connection
                Socket client = new_socket.accept();
                log.info("***New client connected***");
                
                // Setting up I/O streams
                BufferedReader clientInput = new BufferedReader(new InputStreamReader(client.getInputStream()));  
                PrintWriter serverOutput = new PrintWriter(client.getOutputStream(), true);
                DataInputStream client_dataIn = new DataInputStream(client.getInputStream());  
                
                // New connection with client
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***");
                if (clientReply.equals("Hello")) 
                {
                    clientChallenge = "***Connected to ORION Registration App server on 10.0.0.3:9999***";
                    log.info("***Connection with client established***");
                    serverOutput.println(clientChallenge);
                    // Get client's next request
                    clientReply = clientInput.readLine();
                    log.info("***Received: " + clientReply + "***");
                }

                // Client is finished with server requests
                if (clientReply.equals("Bye")) 
                {
                    clientChallenge = "Socket closed";
                    log.info("***Sending: " + clientChallenge + "***");
                    serverOutput.println(clientChallenge);
                    // Close the socket connection
                    client.close();
                    running = false;
                    log.info("Connection to client closed");                     
                }

                // Expedited device registration
                if (clientReply.equals("expedited_device")) 
                {
                    // Request client authentication and device info
                    clientChallenge = "OK - Authenticate";
                    log.info("***Sending: " + clientChallenge + "***");
                    serverOutput.println(clientChallenge);

                    // Expecting user EDIPI, device serial number, and biometric ("password")
                    clientReply = clientInput.readLine();
                    log.info("***Received: " + clientReply + "***");

                    // Parse client's response
                    String [] login_info = clientReply.split(",");
                    String CN = login_info[0];
                    String edipi = login_info[1]; 
                    String fingerprint = login_info[2]; 
                    String serialNumber = login_info[3];
                    String email = login_info[4];

                    // Compare "fingerprint" associated to edipi in simulated database
                    // Device serial number would be temporarily linked to user in database
                    String edipi_db = biometric_database(fingerprint);

                    // If "fingerprint" doesn't match, authentication fails
                    if (!edipi_db.equals(edipi)) 
                    {     
              
                        // Biometric data not in database
                        log.info("***Authentication failed***");
                        clientChallenge = "Authentication failed";
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);

                        // Close the socket connection
                        client.close();
                        log.info("Connection to client closed");
                        System.exit(1);
                    }

                    // Let client know that user and device received/verified
                    log.info("***User and device information received***");
                    clientChallenge = "OK - Verified";
                    log.info("***Sending: " + clientChallenge + "***");
                    serverOutput.println(clientChallenge);
                    clientReply = clientInput.readLine();
                    
                    // Filename of file to be received from client
                    log.info("***Client send request: " + clientReply + "***");             

                    try
                    {   
                        // Send message signal to begin file transfer
                        clientChallenge = "OK - Send";
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);

                        String filename = clientReply;
                        rx_file(filename);

                        // Client signals initiation of challenge p7
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientChallenge + "***");

                        // Extract client public certificate from p12
                        // Run Linux CLI command for OpenSSL to extract crt from p12
                        String tempCert = "temp.crt";
                        String Command = "openssl pkcs12 -in " + filename + " -out " + tempCert + " -password pass:password";                        
                        Process proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();
                        log.info("***Extracted client's public key certificate from P12: " + tempCert + "***");

                        // Create p7 containing a challenge password and encrypt with client's public key
                        String p7 = "challenge.p7";
                        String challengeFile = "challenge.txt";

                        // Generate random challenge password and save to text file
                        String challenge;
                        int pw_length = 20;
                        BufferedWriter pw_out = new BufferedWriter(new FileWriter("/home/orion/ServerDB/" + challengeFile));
                        pw_out.write(generate_challengePW(pw_length));
                        pw_out.close();
                        
                        // Generate p7 containing client challenge password
                        Command = "openssl smime -encrypt -in " + challengeFile + " -outform pem -out " + p7 + " " + tempCert;
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();
                        log.info("***Created encrypted P7 containing client challenge password: " + p7 + "***");

                        // Send challenge p7 file info
                        long file_size = fileSize(p7);
                        clientChallenge = p7 + " " + String.valueOf(file_size);
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);

                        // Client signals ready
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientReply + "***");
                        
                        // Send challenge p7
                        send_p7(p7);

                        // Receive signed p7 from client
                        clientReply = clientInput.readLine();
                        log.info("***Client send request: " + clientReply + "***");   

                        // Send message signal to begin file transfer
                        clientChallenge = "OK - Send";
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);

                        // P7 successfuly received
                        filename = clientReply;
                        rx_file(filename);
                        
                        clientChallenge = "OK - Received";
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);
                        
                        // Verify authenticity of client's p7 message
                        Command = "openssl smime -verify -in " + filename + " -inform pem -noverify";
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();
                        log.info("***Verification successful: " + filename + " authenticated***");

                        // Create encrypted SCEP instructions in p7 contained within ca_info.txt (ip port hash)
                        p7 = "scep.p7";
                        challengeFile = "ca_info.txt";
                        Command = "openssl smime -encrypt -in " + challengeFile + " -outform pem -out " + p7 + " " + tempCert;
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();
                        log.info("***Created encrypted P7 containing client SCEP instructions: " + p7 + "***");
                        

                        // Client signals SCEP request initiation  
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientReply + "***");

                        // Send SCEP p7 file info
                        file_size = fileSize(p7);
                        clientChallenge = p7 + " " + String.valueOf(file_size);
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);

                        // Client signals ready
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientReply + "***");

                        // Send SCEP p7
                        send_p7(p7);

                        // CA receives GETCACERT request and sends p12 containing CA public certificate
                        scepCA();

                        // CA receives CSR, CA generates signed device certificate and sends to client
                        deviceCert(CN);
                        
                        // Client signals initiation of second challenge p7
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientChallenge + "***");

                        // ORA receives copy of new device certificate
                        String deviceCert = CN + ".device.crt";
                        Command = "cp " + deviceCert + " /home/orion/ServerDB";
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA"));
                        proc.waitFor();

                        // Create p7 containing a challenge password and encrypt with client's new device public certificate
                        p7 = "challenge2.p7";
                        challengeFile = "challenge2.txt";

                        // Generate random challenge password and save to text file
                        pw_out = new BufferedWriter(new FileWriter("/home/orion/ServerDB/" + challengeFile));
                        pw_out.write(generate_challengePW(pw_length));
                        pw_out.close();
                        
                        // Generate p7 containing client challenge password
                        Command = "openssl smime -encrypt -in " + challengeFile + " -outform pem -out " + p7 + " " + deviceCert;
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();
                        log.info("***Created encrypted P7 containing client challenge password: " + p7 + "***");

                        // Send challenge p7 file info
                        file_size = fileSize(p7);
                        clientChallenge = p7 + " " + String.valueOf(file_size);
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);

                        // Client signals ready
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientReply + "***");

                        // Send challenge p7
                        send_p7(p7);

                        // Receive signed p7 from client
                        clientReply = clientInput.readLine();
                        log.info("***Client send request: " + clientReply + "***");   

                        // Send message signal to begin file transfer
                        clientChallenge = "OK - Send";
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);
                  
                        filename = clientReply;
                        rx_file(filename);
 
                        // P7 successfuly received
                        clientChallenge = "OK - Received";
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);

                        // Verify authenticity of client's p7 message
                        Command = "openssl smime -verify -in " + filename + " -inform pem -noverify";
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();
                        log.info("***Verification successful: " + filename + " authenticated***");

                        // Expecting user biometric minutia
                        fingerprint = clientInput.readLine();
                        log.info("***Received-- biometric data: " + fingerprint + "***");

                        // Compare "fingerprint" associated to edipi in database
                        edipi_db = biometric_database(fingerprint);

                        // If "fingerprint" doesn't match, authentication fails
                        if (!edipi_db.equals(edipi)) 
                        {                       
                            // Biometric data not in database
                            log.info("***Authentication failed***");
                            clientChallenge = "Authentication failed";
                            log.info("***Sending: " + clientChallenge + "***");
                            serverOutput.println(clientChallenge);

                            // Close the socket connection
                            client.close();
                            log.info("Connection to client closed");
                            System.exit(1);
                        }

                        // Let client know that device certificate enrollment is successful
                        log.info("***User information received***");
                        clientChallenge = "OK - Verified";
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);

                        // ####################################### //
                        /* CONTINUING WITH EXPEDITED CREDENTIALING */
                        // ####################################### //

                        // Expecting user biometric minutia
                        fingerprint = clientInput.readLine();
                        log.info("***Received biometric data: " + fingerprint + "***");

                        // Compare "fingerprint" associated to edipi in database
                        edipi_db = biometric_database(fingerprint);

                        // If "fingerprint" doesn't match, authentication fails
                        if (!edipi_db.equals(edipi)) 
                        {                       
                            // Biometric data not in database
                            log.info("***Authentication failed***");
                            clientChallenge = "Authentication failed";
                            log.info("***Sending: " + clientChallenge + "***");
                            serverOutput.println(clientChallenge);

                            // Close the socket connection
                            client.close();
                            log.info("Connection to client closed");
                            System.exit(1);
                        }

                        // Let client know that biometric authentication successful
                        log.info("***User information received***");
                        clientChallenge = "OK - Verified";
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);

                        // ##################### //
                        // PIV Auth CERTIFICATE //
                        // ##################### //

                        // Create encrypted SCEP instructions for ID CA in p7 
                        p7 = "scep.p7";
                        challengeFile = "idca_info.txt";
                        Command = "openssl smime -encrypt -in " + challengeFile + " -outform pem -out " + p7 + " " + deviceCert;
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();
                        log.info("***Created encrypted P7 containing client SCEP instructions: " + p7 + "***");

                        // Client signals SCEP request initiation  
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientReply + "***");

                        // Send SCEP p7 file info
                        file_size = fileSize(p7);
                        clientChallenge = p7 + " " + String.valueOf(file_size);
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);

                        // Send SCEP p7
                        send_p7(p7);

                        // Client signals ready
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientReply + "***");

                        // CA receives GETCACERT request and sends p12 containing CA public certificate
                        pivCA();

                        // CA receives CSR, CA generates signed PIV authentication certificate and sends to client
                        pivCert(CN);
                        
                        // ORA receives copy of new PIV authentication certificate
                        String pivCert = CN + "piv.crt";
                        Command = "cp " + pivCert + " /home/orion/ServerDB";
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA"));
                        proc.waitFor();   

                        // ##################### //
                        // SIGNATURE CERTIFICATE //
                        // ##################### //

                        // Create encrypted SCEP instructions for EMAIL CA in p7 
                        p7 = "scep.p7";
                        challengeFile = "emailca_info.txt";
                        Command = "openssl smime -encrypt -in " + challengeFile + " -outform pem -out " + p7 + " " + deviceCert;
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();
                        log.info("***Created encrypted P7 containing client SCEP instructions: " + p7 + "***");

                        // Client signals SCEP request initiation  
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientReply + "***");

                        // Send SCEP p7 file info
                        file_size = fileSize(p7);
                        clientChallenge = p7 + " " + String.valueOf(file_size);
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);

                        // Client signals ready
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientReply + "***");

                        // Send SCEP p7
                        send_p7(p7);

                        // CA receives GETCACERT request and sends p12 containing CA public certificate
                        signatureCA();

                        // CA receives CSR, CA generates signed digital signature certificate and sends to client
                        signatureCert(CN);
                        
                        // ORA receives copy of new digital signature certificate
                        String signatureCert = CN + "signature.crt";
                        Command = "cp " + signatureCert + " /home/orion/ServerDB";
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA"));
                        proc.waitFor();

                        // ###################### //
                        // ENCRYPTION CERTIFICATE //
                        // ###################### //

                        // Create encrypted SCEP instructions for EMAIL CA in p7 
                        p7 = "scep.p7";
                        challengeFile = "emailca_info.txt";
                        Command = "openssl smime -encrypt -in " + challengeFile + " -outform pem -out " + p7 + " " + deviceCert;
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();
                        log.info("***Created encrypted P7 containing client SCEP instructions: " + p7 + "***");

                        // Client signals SCEP request initiation  
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientReply + "***");

                        // Send SCEP p7 file info
                        file_size = fileSize(p7);
                        clientChallenge = p7 + " " + String.valueOf(file_size);
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);

                        // Client signals ready
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientReply + "***");

                        // Send SCEP p7
                        send_p7(p7);

                        // CA receives GETCACERT request and sends p12 containing CA public certificate
                        signatureCA();

                        // Server generates new encryption key pair
                        String encryptionKey = CN + ".encryption.key";
                        Command = "openssl genrsa -out " + encryptionKey + " 2048";
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();
                        log.info("***Created encryption RSA 2048 private key: " + encryptionKey + "***");

                        // Server generates encryption certificate CSR
                        String csr = CN + ".encryption.csr";
                        Command = "openssl req -new -key " + encryptionKey + " -out " + csr + " -subj /C=US/OU=USMC/O=U.S.GOVERNMENT/CN=" + CN + "/emailAddress=" + email + " -addext keyUsage=keyEncipherment";
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();
                        log.info("***Created Encryption Certificate Signing Request: " + csr + "***");
                        
                        // CA signs CSR and generates encryption certificate
                        // Copy CSR file into CA directory
                        Command = "cp " + csr + " /home/orion/CA";
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();

                        // Decode CSR and generate signed encryption certificate
                        String encryptionCert = CN + ".encryption.crt";
                        String p12 = "encryptionCert.pfx";
                        String CAprivatekey = "EMAILCA.key";
                        String CApubkey = "EMAILCA.crt";

                        Command = "openssl x509 -req -days 365 -in " + csr + " -CA " + CApubkey + " -CAkey " + CAprivatekey + " -CAcreateserial -sha256 -out " + encryptionCert;
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA"));
                        proc.waitFor();
                        log.info("***Created Signed Encryption Certificate for client: " + encryptionCert + "***");                     

                        // ORA receives copy of new encryption certificate
                        Command = "cp " + encryptionCert + " /home/orion/ServerDB";
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA"));
                        proc.waitFor();

                        // Client signals ready
                        clientChallenge = p12;
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientReply + "***");

                        // Package encryption certificate in p12 and sent to client
                        encryptionCert(CN);

                        // Encrypt encryption private key for tranport
                        String encryptedKey = CN + ".encryption.key";
                        Command = "openssl rsa -aes256 -in " + encryptionKey + " -out " + encryptedKey + " -passout pass:password";
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();
                        log.info("***Encryption private key encrypted for transport: " + encryptedKey + "***");

                        // Package key inside p7
                        p7 = "encryptionKey.p7";
                        Command = "openssl smime -encrypt -in " + encryptedKey + " -outform pem -out " + p7 + " " + deviceCert;
                        proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                        proc.waitFor();
                        log.info("***Created encrypted P7 containing client's encrypted private key: " + p7 + "***");

                        // Client signals initiation of encryptionKey p7
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientChallenge + "***");

                        // Send p7 file info
                        file_size = fileSize(p7);
                        clientChallenge = p7 + " " + String.valueOf(file_size);
                        log.info("***Sending: " + clientChallenge + "***");
                        serverOutput.println(clientChallenge);

                        // Client signals ready
                        clientReply = clientInput.readLine();
                        log.info("***Client: " + clientReply + "***");

                        // Send p7 to client
                        send_p7(p7);

                    } 
                    catch(Exception e)
                    {       
                        //e.printStackTrace();
                        //log.info(e.getStackTrace().toString());
                        log.info("***File transfer failed***");
                    }

                }      
            }
        } 
        catch (Exception e) 
        {
            e.printStackTrace();
        }
        
    }

    public void encryptionCert(String CN)
    {
        String clientReply; // Rx from client
        String clientChallenge; // Tx to client
        String encryptionCert = CN + ".encryption.crt";
        String p12 = "encryptionCert.pfx";
        String Command;        

        try
        {
            // Open new TCP connection
            ServerSocket new_socket = new ServerSocket();
            SocketAddress ora_server = new InetSocketAddress("10.0.0.3", 8888);
	        
            // Bind server socket
            new_socket.bind(ora_server);             
            log.info("***ORION Registration App server listening on port 8888***");
          
            // Accept client connection
            Socket client = new_socket.accept();
            log.info("***New client connected***");

            BufferedReader clientInput = new BufferedReader(new InputStreamReader(client.getInputStream()));  
            PrintWriter serverOutput = new PrintWriter(client.getOutputStream(), true);

            // New connection with client
            clientReply = clientInput.readLine();
            log.info("***Received: " + clientReply + "***");
            if (clientReply.equals("Hello")) 
            {
                clientChallenge = "***Connected to ORION Registration App server on 10.0.0.3:8888***";
                log.info("***Connection with client established***");
                serverOutput.println(clientChallenge);

                // Client sends cert request
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***");             

                // Package encryption certificate inside p12
                Command = "openssl pkcs12 -export -nokeys -out " + p12 + " -in " + encryptionCert + " -password pass:password";
                Process proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB/"));
                proc.waitFor();                
                log.info("***Created P12 containing " + encryptionCert + ": " + p12 + "***");
                
                // ACK the request            
                long file_size = fileSize(p12);
                clientChallenge = p12 + " " + String.valueOf(file_size);
                log.info("***Sending: " + clientChallenge + "***");
                serverOutput.println(clientChallenge); 
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***");  

                // Send p12
                File p12_file = new File("/home/orion/ServerDB/" + p12);
                OutputStream client_dataOut = client.getOutputStream();
                InputStream p12_in = new FileInputStream(p12_file);
                byte[] p12_buffer = new byte[4096];
                log.info("***Sending Encryption Certificate in P12 file to client***");
                int moreData = 0;
                moreData = p12_in.read(p12_buffer, 0, p12_buffer.length);
                client_dataOut.write(p12_buffer, 0, moreData);
                client_dataOut.flush();
                client_dataOut.close();
                log.info("***P12 sent: " + p12 + "***");
                client.close(); 
                p12_in.close();                
                clientInput.close();
                serverOutput.close();    
                new_socket.close();
                log.info("***Socket closed***"); 
            }
        }
        catch (Exception e) 
        {
            e.printStackTrace();
        }
    }

    public void signatureCert(String CN)
    {
        String clientReply; // Rx from client
        String clientChallenge; // Tx to client
        String filename;
        String Command;

        try
        {
            // Open new TCP connection
            ServerSocket new_socket = new ServerSocket();
            SocketAddress ora_server = new InetSocketAddress("10.0.0.3", 5555);
	        
            // Bind server socket
            new_socket.bind(ora_server);             
            log.info("***SCEP EMAIL CA listening on port 5555***");
          
            // Accept client connection
            Socket client = new_socket.accept();
            log.info("***New client connected***");

            BufferedReader clientInput = new BufferedReader(new InputStreamReader(client.getInputStream()));  
            PrintWriter serverOutput = new PrintWriter(client.getOutputStream(), true);
            DataInputStream client_dataIn = new DataInputStream(client.getInputStream()); 

            // New connection with client
            clientReply = clientInput.readLine();
            log.info("***Received: " + clientReply + "***");
            if (clientReply.equals("Hello")) 
            {
                clientChallenge = "***Connected to ORION SCEP EMAIL CA on 10.0.0.3:5555***";
                log.info("***Connection with client established***");
                serverOutput.println(clientChallenge);

                // Receive client's CSR
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***"); 

                filename = clientReply;
                File client_csr = new File("/home/orion/ServerDB/" +  filename);
                client_csr.createNewFile();
                FileOutputStream rcvFile = new FileOutputStream(client_csr);

                // Send message signal to begin file transfer
                clientChallenge = "OK - Send";
                log.info("***Sending: " + clientChallenge + "***");
                serverOutput.println(clientChallenge);
                
                // Write contents to file
                byte[] file_buffer = new byte[4096];
                int moreData = 0;
                moreData = client_dataIn.read(file_buffer, 0, file_buffer.length);
                rcvFile.write(file_buffer, 0, moreData);
                rcvFile.flush();
                rcvFile.close();
                log.info("***CSR Received: " + filename + "***");
                                           
                // CSR successfuly received
                clientChallenge = "OK - Received";
                log.info("***Sending: " + clientChallenge + "***");
                serverOutput.println(clientChallenge);
            
                // Copy CSR file into CA directory
                Command = "cp " + filename + " /home/orion/CA";
                Process proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                proc.waitFor();

                // Decode CSR and generate signed digital signature certificate
                String deviceCert = CN + ".signature.crt";
                String p12 = "signatureCert.pfx";
                String csr = filename;
                String CAprivatekey = "EMAILCA.key";
                String CApubkey = "EMAILCA.crt";

                Command = "openssl x509 -req -days 365 -in " + csr + " -CA " + CApubkey + " -CAkey " + CAprivatekey + " -CAcreateserial -sha256 -out " + deviceCert;
                proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA"));
                log.info("***Created Signed Digital Signature Certificate for client: " + deviceCert + "***");
                proc.waitFor();

                // Package signed digital signature certificate inside p12
                Command = "openssl pkcs12 -export -nokeys -out " + p12 + " -in " + deviceCert + " -password pass:password";
                proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA"));
                proc.waitFor();
                log.info("***Created P12 containing " + deviceCert + ": " + p12 + "***");

                // Inform client of incoming p12
                long file_size = ca_fileSize(p12);
                clientChallenge = p12 + " " + String.valueOf(file_size);
                log.info("***Sending: " + clientChallenge + "***");
                serverOutput.println(clientChallenge); 
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***");  

                // Send p12 containing subscriber digital signature certificate
                File p12_file = new File("/home/orion/CA/" + p12);
                OutputStream client_dataOut = client.getOutputStream();
                InputStream p12_in = new FileInputStream(p12_file);
                byte[] p12_buffer = new byte[4096];
                log.info("***Sending Digital Signature Certificate in P12 file to client***");
                moreData = p12_in.read(p12_buffer, 0, p12_buffer.length);
                client_dataOut.write(p12_buffer, 0, moreData);
                client_dataOut.flush();
                client_dataOut.close();
                log.info("***P12 sent: " + p12 + "***");
                client.close(); 
                p12_in.close();                
                clientInput.close();
                serverOutput.close();    
                new_socket.close();
                log.info("***Socket closed***"); 
            }
        }
        catch (Exception e) 
        {
            e.printStackTrace();
        }
    }

    public void signatureCA()
    {
        // CA key pair already pre-generated as would be expected in real-time application
        // openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout CA.key -out CA.crt
        String clientReply; // Rx from client
        String clientChallenge; // Tx to client
        String caCert = "EMAILCA.crt";
        String p12 = "EMAILcaCert.pfx";
        String Command;        

        try
        {
            // Open new TCP connection
            ServerSocket new_socket = new ServerSocket();
            SocketAddress ora_server = new InetSocketAddress("10.0.0.3", 5555);
	        
            // Bind server socket
            new_socket.bind(ora_server);             
            log.info("***SCEP EMAIL CA listening on port 5555***");
          
            // Accept client connection
            Socket client = new_socket.accept();
            log.info("***New client connected***");

            BufferedReader clientInput = new BufferedReader(new InputStreamReader(client.getInputStream()));  
            PrintWriter serverOutput = new PrintWriter(client.getOutputStream(), true);

            // New connection with client
            clientReply = clientInput.readLine();
            log.info("***Received: " + clientReply + "***");
            if (clientReply.equals("Hello")) 
            {
                clientChallenge = "***Connected to ORION SCEP EMAIL CA on 10.0.0.3:5555***";
                log.info("***Connection with client established***");
                serverOutput.println(clientChallenge);

                // Client sends GETCACERT request
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***");             

                // Package EMAIL CA public certificate inside p12
                Command = "openssl pkcs12 -export -nokeys -out " + p12 + " -in " + caCert + " -password pass:password";
                Process proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA/"));
                proc.waitFor();
                log.info("***Created P12 containing " + caCert + ": " + p12 + "***");
                
                // ACK the request            
                long file_size = ca_fileSize(p12);
                clientChallenge = p12 + " " + String.valueOf(file_size);
                log.info("***Sending: " + clientChallenge + "***");
                serverOutput.println(clientChallenge); 
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***");  

                // Send p12
                File p12_file = new File("/home/orion/CA/" + p12);
                OutputStream client_dataOut = client.getOutputStream();
                InputStream p12_in = new FileInputStream(p12_file);
                byte[] p12_buffer = new byte[4096];
                log.info("***Sending EMAIL CA public certificate in P12 file to client***");
                int moreData = 0;
                moreData = p12_in.read(p12_buffer, 0, p12_buffer.length);
                client_dataOut.write(p12_buffer, 0, moreData);
                client_dataOut.flush();
                client_dataOut.close();
                log.info("***P12 sent: " + p12 + "***");
                client.close(); 
                p12_in.close();                
                clientInput.close();
                serverOutput.close();    
                new_socket.close();
                log.info("***Socket closed***"); 
            }
        }
        catch (Exception e) 
        {
            e.printStackTrace();
        }
    }

    public void pivCert(String CN)
    {
        String clientReply; // Rx from client
        String clientChallenge; // Tx to client
        String filename;
        String Command;

        try
        {
            // Open new TCP connection
            ServerSocket new_socket = new ServerSocket();
            SocketAddress ora_server = new InetSocketAddress("10.0.0.3", 6666);
	        
            // Bind server socket
            new_socket.bind(ora_server);             
            log.info("***SCEP ID CA listening on port 6666***");
          
            // Accept client connection
            Socket client = new_socket.accept();
            log.info("***New client connected***");

            BufferedReader clientInput = new BufferedReader(new InputStreamReader(client.getInputStream()));  
            PrintWriter serverOutput = new PrintWriter(client.getOutputStream(), true);
            DataInputStream client_dataIn = new DataInputStream(client.getInputStream()); 

            // New connection with client
            clientReply = clientInput.readLine();
            log.info("***Received: " + clientReply + "***");
            if (clientReply.equals("Hello")) 
            {
                clientChallenge = "***Connected to ORION SCEP ID CA on 10.0.0.3:6666***";
                log.info("***Connection with client established***");
                serverOutput.println(clientChallenge);

                // Receive client's CSR
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***"); 

                filename = clientReply;
                File client_csr = new File("/home/orion/ServerDB/" +  filename);
                client_csr.createNewFile();
                FileOutputStream rcvFile = new FileOutputStream(client_csr);

                // Send message signal to begin file transfer
                clientChallenge = "OK - Send";
                log.info("***Sending: " + clientChallenge + "***");
                serverOutput.println(clientChallenge);
                
                // Write contents to file
                byte[] file_buffer = new byte[4096];
                int moreData = 0;
                moreData = client_dataIn.read(file_buffer, 0, file_buffer.length);
                rcvFile.write(file_buffer, 0, moreData);
                rcvFile.flush();
                rcvFile.close();
                log.info("***CSR Received: " + filename + "***");
                                           
                // CSR successfuly received
                clientChallenge = "OK - Received";
                log.info("***Sending: " + clientChallenge + "***");
                serverOutput.println(clientChallenge);
            
                // Copy CSR file into CA directory
                Command = "cp " + filename + " /home/orion/CA";
                Process proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                proc.waitFor();

                // Decode CSR and generate signed PIV authentication certificate
                String deviceCert = CN + ".device.crt";
                String p12 = "pivCert.pfx";
                String csr = filename;
                String CAprivatekey = "IDCA.key";
                String CApubkey = "IDCA.crt";

                Command = "openssl x509 -req -days 365 -in " + csr + " -CA " + CApubkey + " -CAkey " + CAprivatekey + " -CAcreateserial -sha256 -out " + deviceCert;
                proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA"));
                proc.waitFor();
                log.info("***Created Signed Device Certificate for client: " + deviceCert + "***");

                // Package signed PIV authentication certificate inside p12
                Command = "openssl pkcs12 -export -nokeys -out " + p12 + " -in " + deviceCert + " -password pass:password";
                proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA"));
                proc.waitFor();
                log.info("***Created P12 containing " + deviceCert + ": " + p12 + "***");

                // Inform client of incoming p12
                long file_size = ca_fileSize(p12);
                clientChallenge = p12 + " " + String.valueOf(file_size);
                log.info("***Sending: " + clientChallenge + "***");
                serverOutput.println(clientChallenge); 
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***");  

                // Send p12 containing subscriber PIV authentication certificate
                File p12_file = new File("/home/orion/CA/" + p12);
                OutputStream client_dataOut = client.getOutputStream();
                InputStream p12_in = new FileInputStream(p12_file);
                byte[] p12_buffer = new byte[4096];
                log.info("***Sending PIV authentication certificate in P12 file to client***");
                moreData = p12_in.read(p12_buffer, 0, p12_buffer.length);
                client_dataOut.write(p12_buffer, 0, moreData);
                client_dataOut.flush();
                client_dataOut.close();
                log.info("***P12 sent: " + p12 + "***");
                client.close(); 
                p12_in.close();                
                clientInput.close();
                serverOutput.close();    
                new_socket.close();
                log.info("***Socket closed***"); 
            }
        }
        catch (Exception e) 
        {
            e.printStackTrace();
        }
    }

    public void pivCA()
    {
        // CA key pair already pre-generated as would be expected in real-time application
        // openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout CA.key -out CA.crt
        String clientReply; // Rx from client
        String clientChallenge; // Tx to client
        String caCert = "IDCA.crt";
        String p12 = "IDcaCert.pfx";
        String Command;        

        try
        {
            // Open new TCP connection
            ServerSocket new_socket = new ServerSocket();
            SocketAddress ora_server = new InetSocketAddress("10.0.0.3", 6666);
	        
            // Bind server socket
            new_socket.bind(ora_server);             
            log.info("***SCEP ID CA listening on port 6666***");
          
            // Accept client connection
            Socket client = new_socket.accept();
            log.info("***New client connected***");

            BufferedReader clientInput = new BufferedReader(new InputStreamReader(client.getInputStream()));  
            PrintWriter serverOutput = new PrintWriter(client.getOutputStream(), true);

            // New connection with client
            clientReply = clientInput.readLine();
            log.info("***Received: " + clientReply + "***");
            if (clientReply.equals("Hello")) 
            {
                clientChallenge = "***Connected to ORION SCEP ID CA on 10.0.0.3:6666***";
                log.info("***Connection with client established***");
                serverOutput.println(clientChallenge);

                // Client sends GETCACERT request
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***");             

                // Package ID CA public certificate inside p12
                Command = "openssl pkcs12 -export -nokeys -out " + p12 + " -in " + caCert + " -password pass:password";
                Process proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA/"));
                proc.waitFor();
                log.info("***Created P12 containing " + caCert + ": " + p12 + "***");
                
                // ACK the request            
                long file_size = ca_fileSize(p12);
                clientChallenge = p12 + " " + String.valueOf(file_size);
                log.info("***Sending: " + clientChallenge + "***");
                serverOutput.println(clientChallenge); 
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***");  

                // Send p12
                File p12_file = new File("/home/orion/CA/" + p12);
                OutputStream client_dataOut = client.getOutputStream();
                InputStream p12_in = new FileInputStream(p12_file);
                byte[] p12_buffer = new byte[4096];
                log.info("***Sending ID CA public certificate in P12 file to client***");
                int moreData = 0;
                moreData = p12_in.read(p12_buffer, 0, p12_buffer.length);
                client_dataOut.write(p12_buffer, 0, moreData);
                client_dataOut.flush();
                client_dataOut.close();
                log.info("***P12 sent: " + p12 + "***");
                client.close(); 
                p12_in.close();                
                clientInput.close();
                serverOutput.close();    
                new_socket.close();
                log.info("***Socket closed***"); 
            }
        }
        catch (Exception e) 
        {
            e.printStackTrace();
        }
    }

    public String generate_challengePW(int pw_length)
    {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            + "abcdefghijklmnopqrstuvwxyz"
                            + "0123456789";
        // create a random string using the character list of pw_length
        StringBuilder new_string = new StringBuilder(pw_length);
        for (int i = 0; i < pw_length; i++) 
        {
            int index = (int)(characters.length()*Math.random());
            new_string.append(characters.charAt(index));
        }
        return new_string.toString();       
    }

    public void deviceCert(String CN)
    {
        String clientReply; // Rx from client
        String clientChallenge; // Tx to client
        String filename;
        String Command;

        try
        {
            // Open new TCP connection
            ServerSocket new_socket = new ServerSocket();
            SocketAddress ora_server = new InetSocketAddress("10.0.0.3", 7777);
	        
            // Bind server socket
            new_socket.bind(ora_server);             
            log.info("***SCEP DEVICE CA listening on port 7777***");
          
            // Accept client connection
            Socket client = new_socket.accept();
            log.info("***New client connected***");

            BufferedReader clientInput = new BufferedReader(new InputStreamReader(client.getInputStream()));  
            PrintWriter serverOutput = new PrintWriter(client.getOutputStream(), true);
            DataInputStream client_dataIn = new DataInputStream(client.getInputStream()); 

            // New connection with client
            clientReply = clientInput.readLine();
            log.info("***Received: " + clientReply + "***");
            if (clientReply.equals("Hello")) 
            {
                clientChallenge = "***Connected to ORION SCEP DEVICE CA on 10.0.0.3:7777***";
                log.info("***Connection with client established***");
                serverOutput.println(clientChallenge);

                // Receive client's CSR
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***"); 

                filename = clientReply;
                File client_csr = new File("/home/orion/ServerDB/" +  filename);
                client_csr.createNewFile();
                FileOutputStream rcvFile = new FileOutputStream(client_csr);

                // Send message signal to begin file transfer
                clientChallenge = "OK - Send";
                log.info("***Sending: " + clientChallenge + "***");
                serverOutput.println(clientChallenge);
                
                // Write contents to file
                byte[] file_buffer = new byte[4096];
                int moreData = 0;
                moreData = client_dataIn.read(file_buffer, 0, file_buffer.length);
                rcvFile.write(file_buffer, 0, moreData);
                rcvFile.flush();
                rcvFile.close();
                log.info("***CSR Received: " + filename + "***");
                                           
                // CSR successfuly received
                clientChallenge = "OK - Received";
                log.info("***Sending: " + clientChallenge + "***");
                serverOutput.println(clientChallenge);
            
                // Copy CSR file into CA directory
                Command = "cp " + filename + " /home/orion/CA";
                Process proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/ServerDB"));
                proc.waitFor();

                // Decode CSR and generate signed device certificate
                String deviceCert = CN + ".device.crt";
                String p12 = "deviceCert.pfx";
                String csr = filename;
                String CAprivatekey = "CA.key";
                String CApubkey = "CA.crt";

                Command = "openssl x509 -req -days 365 -in " + csr + " -CA " + CApubkey + " -CAkey " + CAprivatekey + " -CAcreateserial -sha256 -out " + deviceCert;
                proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA"));
                proc.waitFor();
                log.info("***Created Signed Device Certificate for client: " + deviceCert + "***");

                // Package signed device public certificate inside p12
                Command = "openssl pkcs12 -export -nokeys -out " + p12 + " -in " + deviceCert + " -password pass:password";
                proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA"));
                proc.waitFor();
                log.info("***Created P12 containing " + deviceCert + ": " + p12 + "***");

                // Inform client of incoming p12
                long file_size = ca_fileSize(p12);
                clientChallenge = p12 + " " + String.valueOf(file_size);
                log.info("***Sending: " + clientChallenge + "***");
                serverOutput.println(clientChallenge); 
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***");  

                // Send p12 containing subscriber device certificate
                File p12_file = new File("/home/orion/CA/" + p12);
                OutputStream client_dataOut = client.getOutputStream();
                InputStream p12_in = new FileInputStream(p12_file);
                byte[] p12_buffer = new byte[4096];
                log.info("***Sending device certificate in P12 file to client***");
                moreData = p12_in.read(p12_buffer, 0, p12_buffer.length);
                client_dataOut.write(p12_buffer, 0, moreData);
                client_dataOut.flush();
                client_dataOut.close();
                log.info("***P12 sent: " + p12 + "***");
                client.close(); 
                p12_in.close();                
                clientInput.close();
                serverOutput.close();    
                new_socket.close();
                log.info("***Socket closed***"); 
            }
        }
        catch (Exception e) 
        {
            e.printStackTrace();
        }
    }

    public void scepCA()
    {
        // CA key pair already pre-generated as would be expected in real-time application
        // openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout CA.key -out CA.crt
        String clientReply; // Rx from client
        String clientChallenge; // Tx to client
        String caCert = "CA.crt";
        String p12 = "caCert.pfx";
        String Command;        

        try
        {
            // Open new TCP connection
            ServerSocket new_socket = new ServerSocket();
            SocketAddress ora_server = new InetSocketAddress("10.0.0.3", 7777);
	        
            // Bind server socket
            new_socket.bind(ora_server);             
            log.info("***SCEP DEVICE CA listening on port 7777***");
          
            // Accept client connection
            Socket client = new_socket.accept();
            log.info("***New client connected***");

            BufferedReader clientInput = new BufferedReader(new InputStreamReader(client.getInputStream()));  
            PrintWriter serverOutput = new PrintWriter(client.getOutputStream(), true);

            // New connection with client
            clientReply = clientInput.readLine();
            log.info("***Received: " + clientReply + "***");
            if (clientReply.equals("Hello")) 
            {
                clientChallenge = "***Connected to ORION SCEP DEVICE CA on 10.0.0.3:7777***";
                log.info("***Connection with client established***");
                serverOutput.println(clientChallenge);

                // Client sends GETCACERT request
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***");             

                // Package CA public certificate inside p12
                Command = "openssl pkcs12 -export -nokeys -out " + p12 + " -in " + caCert + " -password pass:password";
                Process proc = Runtime.getRuntime().exec(Command, null, new File("/home/orion/CA/"));
                proc.waitFor();
                log.info("***Created P12 containing " + caCert + ": " + p12 + "***");
                
                // ACK the request            
                long file_size = ca_fileSize(p12);
                clientChallenge = p12 + " " + String.valueOf(file_size);
                log.info("***Sending: " + clientChallenge + "***");
                serverOutput.println(clientChallenge); 
                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***");  

                // Send p12
                File p12_file = new File("/home/orion/CA/" + p12);
                OutputStream client_dataOut = client.getOutputStream();
                InputStream p12_in = new FileInputStream(p12_file);
                byte[] p12_buffer = new byte[4096];
                log.info("***Sending DEVICE CA public certificate in P12 file to client***");
                int moreData = 0;
                moreData = p12_in.read(p12_buffer, 0, p12_buffer.length);
                client_dataOut.write(p12_buffer, 0, moreData);
                client_dataOut.flush();
                client_dataOut.close();
                log.info("***P12 sent: " + p12 + "***");
                client.close(); 
                p12_in.close();                
                clientInput.close();
                serverOutput.close();    
                new_socket.close();
                log.info("***Socket closed***"); 
            }
        }
        catch (Exception e) 
        {
            e.printStackTrace();
        }
    }
    
    public void rx_file(String fileName)
    {
        String clientReply; // Rx from client
        String clientChallenge; // Tx to client
        try
        {
            // Open new TCP connection
            ServerSocket new_socket = new ServerSocket();
            SocketAddress ora_server = new InetSocketAddress("10.0.0.3", 8888);
	        
            // Bind server socket
            new_socket.bind(ora_server);             
            log.info("***Server listening on port 8888***");
          
            // Accept client connection
            Socket client = new_socket.accept();
            log.info("***New client connected***");

            BufferedReader clientInput = new BufferedReader(new InputStreamReader(client.getInputStream()));  
            PrintWriter serverOutput = new PrintWriter(client.getOutputStream(), true);
            DataInputStream client_dataIn = new DataInputStream(client.getInputStream()); 

            // New connection with client
            clientReply = clientInput.readLine();
            log.info("***Received: " + clientReply + "***");
            if (clientReply.equals("Hello")) 
            {
                clientChallenge = "***Connected to ORION Registration App server on 10.0.0.3:8888***";
                log.info("***Connection with client established***");
                serverOutput.println(clientChallenge);

                // Receive and write contents to file
                File client_file = new File("/home/orion/ServerDB/" +  fileName);
                client_file.createNewFile();
                FileOutputStream rcvFile = new FileOutputStream(client_file);
                byte[] file_buffer = new byte[4096];
                int moreData = 0;
                moreData = client_dataIn.read(file_buffer, 0, file_buffer.length);
                rcvFile.write(file_buffer, 0, moreData);
                rcvFile.flush();
                rcvFile.close();
                log.info("***File Received: " + fileName + "***");
                clientInput.close();
                serverOutput.close(); 
                new_socket.close();
                log.info("***Socket closed***");  
            }
        }
        catch (Exception e) 
        {
            e.printStackTrace();
            log.info("***File transfer failed: " + fileName + "***");
        }
    }
    
    public void send_p7(String p7)
    {   
        String clientReply; // Rx from client
        String clientChallenge; // Tx to client
        try
        {
            // Open new TCP connection
            ServerSocket new_socket = new ServerSocket();
            SocketAddress ora_server = new InetSocketAddress("10.0.0.3", 8888);
	        
            // Bind server socket
            new_socket.bind(ora_server);             
            log.info("***Server listening on port 8888***");
          
            // Accept client connection
            Socket client = new_socket.accept();
            log.info("***New client connected***");

            BufferedReader clientInput = new BufferedReader(new InputStreamReader(client.getInputStream()));  
            PrintWriter serverOutput = new PrintWriter(client.getOutputStream(), true);

            // New connection with client
            clientReply = clientInput.readLine();
            log.info("***Received: " + clientReply + "***");
            if (clientReply.equals("Hello")) 
            {
                clientChallenge = "***Connected to ORION Registration App server on 10.0.0.3:8888***";
                log.info("***Connection with client established***");
                serverOutput.println(clientChallenge);

                clientReply = clientInput.readLine();
                log.info("***Received: " + clientReply + "***");

                // Send the p7
                File p7_file = new File("/home/orion/ServerDB/" + p7);
                OutputStream client_dataOut = client.getOutputStream();
                InputStream p7_in = new FileInputStream(p7_file);
                byte[] p7_buffer = new byte[8192];
                log.info("***Sending file to client***");
                int moreData = 0;
                moreData = p7_in.read(p7_buffer, 0, p7_buffer.length);
                client_dataOut.write(p7_buffer, 0, moreData);
                client_dataOut.flush();
                client_dataOut.close();
                log.info("***File sent: " + p7 + "***");
                client.close(); 
                p7_in.close();                
                clientInput.close();
                serverOutput.close();    
                new_socket.close();
                log.info("***Socket closed***");         
            }
        }
        catch (Exception e) 
        {
            e.printStackTrace();
            log.info("***p7 transfer failed***");
        }
    }

    public static void wait(int ms)
    {
        try
        {   
            Thread.sleep(ms);
        }
        catch(InterruptedException ex)
        {
            Thread.currentThread().interrupt();
        }
    }

    public long ca_fileSize(String fileName)
    {
        File file = new File("/home/orion/CA/" + fileName);
        return file.length();
    }

    public long fileSize(String fileName)
    {
        File file = new File("/home/orion/ServerDB/" + fileName);
        return file.length();
    }

    public String biometric_database(String fingerprint) 
    {
        // Simulate database info containing EDIPI linked to biometric modality
        HashMap<String, String> biometric_db = new HashMap<String, String>();
        biometric_db.put("password", "1234567890"); // <biometric, edipi>
        
        // Check if database contains the passed in fingerprint input
        boolean validKey = biometric_db.containsKey(fingerprint);
        if (validKey) 
        {
            String value = (String)biometric_db.get(fingerprint);
            return value;
        }
        else 
        {
            String value = "null";
            return value;
        }
    }
    
    @Activate
    protected void activate() 
    {
        log.info("***Started ORION Regisration Application server***");
        orion_server();
    }

    @Deactivate
    protected void deactivate() 
    {
        log.info("***Stopped ORION Regisration Application server***");
    }

}
