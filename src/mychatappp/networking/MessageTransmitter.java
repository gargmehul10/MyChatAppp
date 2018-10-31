/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mychatappp.networking;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
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
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.JOptionPane;
import mychatappp.security.AES;
import mychatappp.security.DES;

/**
 *
 * @author Mehul Garg
 */
public class MessageTransmitter extends Thread{

    String message = "", hostname, choice = "AES";
    int port;
    File file = null;
    WritableGUI gui;
    String pubKeyRSA_sender;
    PrivateKey privateKeyRSA_sender;
    
    public MessageTransmitter(){
        
    }
    
    public MessageTransmitter(WritableGUI gui, String message, String hostname, int port, String choice, String pubKeyRSA_sender, PrivateKey privateKeyRSA_sender){
        this.gui = gui;
        this.message = message;
        this.hostname = hostname;
        this.port = port;
        this.choice = choice;
        this.pubKeyRSA_sender = pubKeyRSA_sender;
        this.privateKeyRSA_sender = privateKeyRSA_sender;
    }
    
    public MessageTransmitter(WritableGUI gui, File file, String hostname, int port, String choice, String pubKeyRSA_sender, PrivateKey privateKeyRSA_sender){
        this.gui = gui;
        this.file = file;
        this.hostname = hostname;
        this.port = port;
        this.choice = choice;
        this.pubKeyRSA_sender = pubKeyRSA_sender;
        this.privateKeyRSA_sender = privateKeyRSA_sender;
    }
    
    private static PublicKey getPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
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
    
    private static byte[] encrypt(String key, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");  
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(key));  

        return cipher.doFinal(message.getBytes());  
    }
    
    public static byte[] encrypt(PrivateKey key, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");  
        cipher.init(Cipher.ENCRYPT_MODE, key);  

        return cipher.doFinal(Base64.getDecoder().decode(message));  
    }
    
    String addSignature(String msg) throws Exception
    {
        try { 
            MessageDigest md = MessageDigest.getInstance("MD5"); 
            byte[] messageDigest = md.digest(Base64.getDecoder().decode(msg)); 
            BigInteger no = new BigInteger(1, messageDigest); 
            String hashtext = no.toString(16); 
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            }
            String encrypted=Base64.getEncoder().encodeToString(encrypt(privateKeyRSA_sender,hashtext));
            System.out.println("Hash Generated (MD5): " + hashtext);
            System.out.println("Encrypted Hash: " + encrypted);
            System.out.println("Digitally Signed Message sent: " + encrypted + msg);
            // System.out.println(encrypted.length());
            return (encrypted + msg); 
        }  
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        }
    }
    
    @Override
    public void run() {
        try {
            Socket s = new Socket(hostname, port);
            System.out.println("Client Connected");
            
            // getting public key (RSA) of receiver to encrypt AES or DES key
            DataInputStream dis=new DataInputStream(s.getInputStream());
            String pubKeyRSA_receiver=dis.readUTF();
            
            // generating AES or DES key
            KeyGenerator keyGen;
            SecretKey key;
            if(choice.equals("AES"))
            {
                keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(128);
                key= keyGen.generateKey();
            }
            else
            {
                key = KeyGenerator.getInstance("DES").generateKey();
            }
            String secretKey=Base64.getEncoder().encodeToString(key.getEncoded());
            
            System.out.println(choice + " key generated: " + secretKey);
            
            // encrypting AES or DES key with public RSA key of the receiver
            String encKey=Base64.getEncoder().encodeToString(encrypt(pubKeyRSA_receiver,secretKey));
           
            System.out.println("Encypted " + choice + " key using RSA: " + encKey);

            if(message.equals(""))
            {
                message = new String(Files.readAllBytes(Paths.get(file.getPath())));
            }
            
            // sending encytpted message using AES or DES key (secretKey)
            DataOutputStream dos=new DataOutputStream(s.getOutputStream());
            String messageCopy = message;
            
            if(choice.equals("AES"))
                message = AES.encrypt(message, secretKey);
            else
                message = DES.encrypt(message, secretKey);
            
            System.out.println("Original Message: " + messageCopy);
            System.out.println("Encrypted Message: " + message);
            
            // generating digital signature using MD-5
            dos.writeUTF(pubKeyRSA_sender);
            dos.writeUTF(addSignature(message));
            
            System.out.println();
                   
            dos.writeUTF(message);
            String finalmessage = "";
            for(int i=0;i<100;i++)
                finalmessage+=" ";
            
            if(file == null)
                gui.write(finalmessage + messageCopy);
            else
                gui.write("\n************************************" + file.getName() + "sent successfully!************************************\n");
            
            // sending encrypted AES or DES key using RSA public key of receiver
            dos.writeUTF(choice + "---" + encKey);
            
            // sending type i.e. message or a file
            if(file == null)
                dos.writeUTF("**Message**");
            else
                dos.writeUTF(file.getName());
               
            
            s.close();
        } catch (IOException ex) {
            Logger.getLogger(MessageTransmitter.class.getName()).log(Level.SEVERE, null, ex);
            
            JOptionPane.showMessageDialog(null, "Can't connect !");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MessageTransmitter.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(MessageTransmitter.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
