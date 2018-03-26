package cs4351;

import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import java.security.MessageDigest;
import java.util.Base64;

public class CryptoMultiEchoServerProtocol {
 // The MultiEchoServer was provided by Yoonsik Cheon at least 10 years ago.
 // It was modified several times by Luc Longpre over the years.
 // This version is augmented by encrypting messages using AES encryption.
 // Used for Computer Security, Spring 2018.  
    public static void main(String[] args) {

        System.out.println("CryptoMultiEchoServer started.");
        int sessionID = 0; // assign incremental session ids to each client connection

        try {
            ServerSocket s = new ServerSocket(8008);
            // The server runs until an error occurs
            // or is stopped externally
            for (;;) {
                Socket incoming = s.accept();
                // start a connection with the client
                // in a new thread and wait for another
                // connection
                new ClientHandler(incoming, ++sessionID).start();
                // start() causes the thread to begin execution
                // the JVM calls the run() method of this thread
            }
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }
        System.out.println("MultiEchoServer stopped.");
    }

    private static class ClientHandler extends Thread {

        protected Socket incoming;
        protected int id;

        public ClientHandler(Socket incoming, int id) {
            this.incoming = incoming;
            this.id = id;
        }

        public void run() {
            try {

                    String publicKey1="";
                    String publicKey2="";
                    String publicSignature="";
                    String certificateServer="";                
                
                // in and out for socket communication using strings
                BufferedReader in
                        = new BufferedReader(
                                new InputStreamReader(incoming.getInputStream()));
                PrintWriter out
                        = new PrintWriter(
                                new OutputStreamWriter(incoming.getOutputStream()));
                // send hello to client
                out.print("Hello! This is Java MultiEchoServer. ");
                out.println("Enter BYE to exit.");
                out.flush();


                System.out.println("Waiting the hello word");
                //*************************************            
                // Receive hello from the client
                //*************************************  
                String messageFromClient = in.readLine();
                if(messageFromClient.equals("hello")){
                    try {   
                        // read and send certificate to client
                        File file = new File("certificate.txt");
                        Scanner input = new Scanner(file);
                        String line;
                        out.println("-----BEGIN INFORMATION-----");
                        while (input.hasNextLine()) {
                            line = input.nextLine();
                            out.println(line);
                        }
                        out.flush();
                    } catch (FileNotFoundException e){
                        System.out.println("certificate file not found");
                        return;
                    }                    
                }
                //*************************************  

                //*************************************
                //Receive client certificate
                //*************************************
                try {

                    int row = 0;
                    String line = in.readLine();
                    VerifyCert.test();
                    while (!"-----END SIGNATURE-----".equals(line)) {
                        line = in.readLine();
                        certificateServer=certificateServer+line+"\n";
                        //5-10
                        if(row>=4 && row<=9){
                            //Public Key 1
                            publicKey1=publicKey1+line+"\n";
                        }else if(row>=10 && row<=15){
                            //Public Key 2
                            publicKey2=publicKey2+line+"\n";
                        //}else if(row>=16 && row<=18){
                        }else if(row==17){    
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



                // We could use Base64 encoding and communicate with strings using in and out
                // However, we show here how to send and receive serializable java objects                    
                ObjectInputStream objectInput = new ObjectInputStream(incoming.getInputStream());
                ObjectOutputStream objectOutput = new ObjectOutputStream(incoming.getOutputStream());
                // read the file of random bytes from which we can derive an AES key

                //*************************************
                //Generating 8 random bytes
                //*************************************
                CreateRandomSecret.generateRandomBytes("random8BytesServer");
                //*************************************

                //*************************************
                //The random bytes are encrypted
                //*************************************
                File file;
                PublicKey pubKey;
                PrivateKey privKey;
                byte[] encrypted8ByteArray;
                String encrypted8Bytes;

                byte[] random8Bytes;
                try {
                    FileInputStream fis8bytes = new FileInputStream("random8BytesServer");
                    random8Bytes = new byte[fis8bytes.available()];
                } catch (Exception e) {
                    System.out.println("problem reading the randomBytes file");
                    return;
                }

                pubKey = PemUtils.readPublicKey("IsmaelVillanuevaClientpublicKey.pem");                
                privKey = PemUtils.readPrivateKey("IsmaelVillanuevaServerprivateKey.pem");                
                encrypted8ByteArray = Encrypt.encrypt(pubKey, random8Bytes);

                //*************************************
                //The random encrypted bytes are sent to the client
                //*************************************
                objectOutput.writeObject(encrypted8ByteArray); 
                //*************************************        
                
                //*************************************
                //8 random bytes hashed using SHA-256
                //*************************************
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hashed8Byte = digest.digest(random8Bytes);  

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
            // The 8 random encrypted bytes are received from the server
            //*************************************
            byte[] encrypted8ByteClient = (byte[]) objectInput.readObject();
            //*************************************

            //*************************************
            // The signature is received from the server
            //*************************************
            byte[] signatureClient = (byte[]) objectInput.readObject();
            //*************************************


                pubKey = PemUtils.readPublicKey("IsmaelVillanuevaClientpublicKey.pem");                
                privKey = PemUtils.readPrivateKey("IsmaelVillanuevaServerprivateKey.pem");    

            //*************************************
            // The client decrypts the server random bytes and verifies the signature
            //*************************************
            byte[] decrypted8ByteClient = Decrypt.decrypt(privKey,encrypted8ByteClient);
            MessageDigest digestClient = MessageDigest.getInstance("SHA-256");
            byte[] decrypted8ByteServerHashed = digest.digest(decrypted8ByteClient);                            
            if (Verify.verify(pubKey, decrypted8ByteServerHashed, signatureClient)){
                System.out.println("Signature verification succeeded");
            }
            else{
                System.out.println("Signature verification failed");                                        
            }
            //*************************************


            //*************************************
            // Both the server and the client generates a 16 bytes 
            // shared secret by creating a 16 bytes array that contains 
            // the server random bytes as the ﬁrst 8 bytes and the 
            // client random bytes as the next 8 bytes.
            //*************************************
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            //Server
            outputStream.write(random8Bytes);
            //Client
            outputStream.write(decrypted8ByteClient);
            byte randomBytes[] = outputStream.toByteArray();

                // get the initialization vector from the client
                // each client will have a different vector
                byte[] iv = (byte[]) objectInput.readObject();
                // we will use AES encryption, CBC chaining and PCS5 block padding
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                
                //*************************************
                Cipher cipherEncrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                //*************************************
                
                // generate an AES key derived from randomBytes array
                SecretKeySpec secretKey = new SecretKeySpec(randomBytes, "AES");
                // initialize with a specific vector instead of a random one
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
                
                //*************************************
                cipherEncrypt.init(Cipher.ENCRYPT_MODE, secretKey);
                byte[] ivEncript = cipherEncrypt.getIV();           
                objectOutput.writeObject(ivEncript); 
                //*************************************
                
                // keep echoing the strings received until
                // receiving the string "BYE" which will break
                // out of the for loop and close the thread
                for (;;) {

                    // get the encrypted bytes from the client as an object
                    byte[] encryptedByte = (byte[]) objectInput.readObject();
                    // decrypt the bytes
                    String str = new String(cipher.doFinal(encryptedByte));
                    // reply to the client with an echo of the string
                    // this reply is not encrypted, you need to modify this
                    // by encrypting the reply

                    //*************************************
                    String messageOriginal = "Echo: " + str;
                    byte[] encryptByte = cipherEncrypt.doFinal(messageOriginal.getBytes());
                    objectOutput.writeObject(encryptByte);
                    //*************************************
                    // print the message received from the client
                    System.out.println("Received from session " + id + ": " + str);
                    if (str.trim().equals("BYE")) {
                        break;
                    }
                }
                System.out.println("Session " + id + " ended.");
                incoming.close();
            } catch (Exception e) {
                System.out.println("Error: " + e);
                e.printStackTrace();
            }
        }
    }
}
