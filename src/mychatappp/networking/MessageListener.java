/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mychatappp.networking;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Writer;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import mychatappp.security.AES;
import mychatappp.security.DES;

/**
 *
 * @author Mehul Garg
 */
public class MessageListener extends Thread{
    
    ServerSocket server;
    int port = 8877;
    WritableGUI gui;
    String pubKeyRSA_receiver;
    PrivateKey privateKeyRSA_receiver;
    
    public MessageListener(WritableGUI gui, int port, String pubKeyRSA, PrivateKey privateKeyRSA)
    {
        this.gui = gui;
        this.port = port;
        this.pubKeyRSA_receiver = pubKeyRSA;
        this.privateKeyRSA_receiver = privateKeyRSA;
        try {
            server = new ServerSocket(port);
        } catch (IOException ex) {
            Logger.getLogger(MessageListener.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public MessageListener()
    {
        try {
            server = new ServerSocket(port);
        } catch (IOException ex) {
            Logger.getLogger(MessageListener.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static PublicKey getPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }
    
    public static byte[] decrypt(String key, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.DECRYPT_MODE, getPublicKey(key));
        return cipher.doFinal(encrypted);
    }
    
    public static byte[] decrypt(PrivateKey key, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encrypted);
    }
    
    boolean verifySignature(String cipher, String oppPublicKeyRSA) throws Exception
    {
        String sig=cipher.substring(0,344);
        String msg=cipher.substring(344);
        System.out.println("Digital Signature recieved: " + sig);
        String hashReceived=Base64.getEncoder().encodeToString(decrypt(oppPublicKeyRSA,Base64.getDecoder().decode(sig)));
        MessageDigest md = MessageDigest.getInstance("MD5"); 
        byte[] messageDigest = md.digest(Base64.getDecoder().decode(msg)); 
        BigInteger no = new BigInteger(1, messageDigest); 
        String hashtext = no.toString(16); 
        while (hashtext.length() < 32) { 
            hashtext = "0" + hashtext; 
        }
        System.out.println("Received Hash: " + hashReceived);
        System.out.println("Hash Generated: " + hashtext);
        if(hashtext.equals(hashReceived))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    
    @Override
    public void run() {
        Socket clientSocket;
        try {
            System.out.println("Starting to Listen...");
            while((clientSocket = server.accept()) != null){
                System.out.println("Connected");
                
                // sending public key to sender
                DataOutputStream dos=new DataOutputStream(clientSocket.getOutputStream());
                dos.writeUTF(pubKeyRSA_receiver);
                
                DataInputStream dis=new DataInputStream(clientSocket.getInputStream());
                
                // reading public key RSA of sender
                String publicKeyRSA_sender = dis.readUTF();
                
                // reading hash or digital signature
                String digitalSignature = dis.readUTF();
                
                System.out.println("Verifying Digital Signature...");
                
                // reading message
                String line = dis.readUTF();
                
                // reading encrypted AES or DES key to decrypt the message
                String encKey = dis.readUTF();
                
                // reading type i.e. message or file
                String type = dis.readUTF(), fileName = null;
                
                if(type.equals("**Message**"))
                    type = "Message";
                else
                {
                    fileName = type;
                    type = "File";
                }
        
                
                if(verifySignature(digitalSignature, publicKeyRSA_sender))
                {
                    System.out.println(type + " verified successfully!");
                    
                    // decyrpt the AES or DES key with the private key of RSA
                    String decKey = new String(decrypt(privateKeyRSA_receiver, Base64.getDecoder().decode(encKey.substring(6))));;
                    
                    // decyrpt the message
                    String choice = encKey.substring(0, 3);
                    System.out.println("Encrypted " + choice + " key received: " + encKey.substring(6));
                    System.out.println("Decrypted " + choice + " key using my private RSA key: " + decKey);
                    
                    System.out.println("Encrypted " + type  + ": " + line);
                    
                    if(choice.equals("AES"))
                        line = AES.decrypt(line, decKey);
                    else
                        line = DES.decrypt(line, decKey);
                
                    System.out.println("Decrypted " + type  + ": " + line);
                    
                    System.out.println();
                    
                    if(line != null){
                        if(type.equals("Message"))
                            gui.write(line);
                        else
                        {   
                            gui.write("\n************************************A file is received.************************************\n");
                             
                            Files.write(Paths.get(System.getProperty("user.dir") + "/" + fileName), line.getBytes());
                        }
                    }
                }
                else
                {
                    JOptionPane.showMessageDialog(new JFrame(), "Digital Signature could not be verified!\nNetwork not secure!");
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(MessageListener.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(MessageListener.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
