package cs4351;

import java.io.*;
import java.net.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.MessageDigest;
import java.util.Base64;

public class CryptoEchoClientProtocol {
 // The MultiEchoServer was provided by Yoonsik Cheon at least 10 years ago.
 // It was modified several times by Luc Longpre over the years.
 // This version is augmented by encrypting messages using AES encryption.
 // Used for Computer Security, Spring 2018.    
    public static void main(String[] args) {



                String publicKey1="";
                String publicKey2="";
                String publicSignature="";
                String certificateServer="";

        String host;
        Scanner userInput = new Scanner(System.in);
        if (args.length > 0) {
            host = args[0];
        } else {
            System.out.println("Enter the server's address: (IP address or \"localhost\")");
            host = userInput.nextLine();
        }
        try {

            Socket socket = new Socket(host, 8008);
            // in and out for socket communication using strings
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            System.out.println(in.readLine());
            PrintWriter out= new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
            // We could use Base64 encoding and communicate with strings using in and out
            // However, we show here how to send and receive serializable java objects
            //*************************************            
            // Send hello to server
            //************************************* 
            out.println("hello");
            out.flush();
            try {

                int row = 0;
                String line = in.readLine();
                VerifyCert.test();
                while (!"-----END SIGNATURE-----".equals(line)) {
                    line = in.readLine();
                    certificateServer=certificateServer+line+"\n";
                    if(row>=4 && row<=9){
                        //Public Key 1
                        publicKey1=publicKey1+line+"\n";
                    }else if(row>=10 && row<=15){
                        //Public Key 2
                        publicKey2=publicKey2+line+"\n";
                    //}else if(row>=16 && row<=18){
                    }else if(row==18){    
                        //Signature
                        publicSignature=publicSignature+line;
                    }
                    row++;
                }

                //*************************************            
                // The certiﬁcate is veriﬁed for format, the signature in the certiﬁcate is veriﬁed.
                //*************************************                 
                String certificateReceived = certificateServer;
                InputStream certificateInput = new ByteArrayInputStream(certificateReceived.getBytes());
                BufferedReader certificateBR = new BufferedReader(new InputStreamReader(certificateInput));
                
                PublicKey[] pk = VerifyCert.vCert(certificateBR);
                if (pk==null)
                    System.out.println("certificate verification failed :(");
                else
                    System.out.println("certificate verification succeeded :)");                
                //*************************************                 
            } catch (IOException e) {
                System.out.println("problem reading the certificate from server");
                return;
            }


            //*************************************
            // read and send certificate to server
            //*************************************
            try{
                File file = new File("certificate.txt");
                Scanner input = new Scanner(file);
                String lineCertificate;
                out.println("-----BEGIN INFORMATION-----");
                while (input.hasNextLine()) {
                    lineCertificate = input.nextLine();
                    out.println(lineCertificate);
                }
                out.flush();
            } catch (FileNotFoundException e){
                System.out.println("certificate file not found");
                return;
            }             
            //*************************************
            ObjectOutputStream objectOutput = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream objectInput = new ObjectInputStream(socket.getInputStream());
            PublicKey pubKey;
            PrivateKey privKey;

            //*************************************
            // The 8 random encrypted bytes are received from the server
            //*************************************
            byte[] encrypted8ByteServer = (byte[]) objectInput.readObject();
            //*************************************

            //*************************************
            // The signature is received from the server
            //*************************************
            byte[] signatureServer = (byte[]) objectInput.readObject();
            //*************************************


                pubKey = PemUtils.readPublicKey("IsmaelVillanuevaServerpublicKey.pem");                
                privKey = PemUtils.readPrivateKey("IsmaelVillanuevaClientprivateKey.pem");    

            //*************************************
            // The client decrypts the server random bytes and verifies the signature
            //*************************************
            byte[] decrypted8ByteServer = Decrypt.decrypt(privKey,encrypted8ByteServer);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] decrypted8ByteServerHashed = digest.digest(decrypted8ByteServer);                            
            if (Verify.verify(pubKey, decrypted8ByteServerHashed, signatureServer)){
                System.out.println("Signature verification succeeded");
            }
            else{
                System.out.println("Signature verification failed");                                        
            }
            //*************************************


                //*************************************
                //Generating 8 random bytes
                //*************************************
                CreateRandomSecret.generateRandomBytes("random8BytesClient");
                //*************************************

                //*************************************
                //The random bytes are encrypted
                //*************************************
                File file;
                //PublicKey pubKey;
                //PrivateKey privKey;
                byte[] encrypted8ByteArray;
                String encrypted8Bytes;

                byte[] random8Bytes;
                try {
                    FileInputStream fis8bytes = new FileInputStream("random8BytesClient");
                    random8Bytes = new byte[fis8bytes.available()];
                } catch (Exception e) {
                    System.out.println("problem reading the randomBytes file");
                    return;
                }              
                encrypted8ByteArray = Encrypt.encrypt(pubKey, random8Bytes);

                //*************************************
                //The random encrypted bytes are sent to the client
                //*************************************
                objectOutput.writeObject(encrypted8ByteArray); 
                //*************************************        
                
                //*************************************
                //8 random bytes hashed using SHA-256
                //*************************************
                MessageDigest digestServer = MessageDigest.getInstance("SHA-256");
                byte[] hashed8Byte = digestServer.digest(random8Bytes);  

                //*************************************
                //Signing the hash
                //*************************************
                Signature sig;
                byte[] signature;
                signature = Sign.sign(privKey, hashed8Byte);

                //*************************************
                //The signature is sent to the client
                //*************************************
                objectOutput.writeObject(signature); 
                //*************************************   



            //*************************************
            // Both the server and the client generates a 16 bytes 
            // shared secret by creating a 16 bytes array that contains 
            // the server random bytes as the ﬁrst 8 bytes and the 
            // client random bytes as the next 8 bytes.
            //*************************************
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            //Server
            outputStream.write(decrypted8ByteServer);
            //Client
            outputStream.write(random8Bytes);
            byte randomBytes[] = outputStream.toByteArray();

            
            // we will use AES encryption, CBC chaining and PCS5 block padding
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            // generate an AES key derived from randomBytes array
            SecretKeySpec secretKey = new SecretKeySpec(randomBytes, "AES");                
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);


            // the initialization vector was generated randomly
            // transmit the initialization vector to the server
            // no need to encrypt the initialization vector
            // send the vector as an object
            byte[] iv = cipher.getIV();           
            objectOutput.writeObject(iv); 

            //*************************************
            Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] ivDecrypt = (byte[]) objectInput.readObject();
            cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(ivDecrypt));
            //*************************************            
            
            System.out.println("Starting messages to the server. Type messages, type BYE to end");            
            boolean done = false;
            while (!done) {
                // Read message from the user
                System.out.println("Send Message: ");
                String userStr = userInput.nextLine();
                // Encrypt the message
                byte[] encryptedByte = cipher.doFinal(userStr.getBytes());
                // Send encrypted message as an object to the server
                objectOutput.writeObject(encryptedByte);
                // If user says "BYE", end session

                if (userStr.trim().equals("BYE")) {
                    System.out.println("client session ended");
                    done = true;
                } else {
                    // Receive the reply from the server and print it
                    // You need to modify this to handle encrypted reply
                    //*************************************
                    byte[] decryptByte = (byte[]) objectInput.readObject();
                    String str = new String(cipherDecrypt.doFinal(decryptByte));
                    System.out.println(str);
                    //*************************************

                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
