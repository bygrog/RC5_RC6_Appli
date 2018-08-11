/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package control;

/**
 *
 * @author D4
 */
import javax.crypto.spec.*;
import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

  
public class RC5
{
   private static String algorithm = "RC5";
   
  
   /*public static void main(String []args) throws Exception {
      Security.addProvider(new BouncyCastleProvider());
      String toEncrypt = "The shorter you live, the longer you're dead!";
  
      System.out.println("Encrypting...");
      byte[] encrypted = encrypt(toEncrypt, "password");
      System.out.println(" byte: "+printbyte(encrypted));
      String text = new String(encrypted,"UTF-8");
      System.out.println(" cipher: "+text);
      byte[] bytetxt = text.getBytes("UTF-8");
      System.out.println(" byte: "+printbyte(bytetxt));
      System.out.println("Decrypting...");
      String decrypted = decrypt(encrypted, "password");
      System.out.println("Decrypted text: " + decrypted);
   }*/
  
   public static byte[] encrypt(String toEncrypt, String key) throws Exception {
      // create a binary key from the argument key (seed)
      SecureRandom sr = new SecureRandom(key.getBytes());
      KeyGenerator kg = KeyGenerator.getInstance(algorithm);
      kg.init(sr);
      SecretKey sk = kg.generateKey();
  
      // create an instance of cipher
      Cipher cipher = Cipher.getInstance(algorithm);
  
      // initialize the cipher with the key
      cipher.init(Cipher.ENCRYPT_MODE, sk);
  
      // enctypt!
      byte[] encrypted = cipher.doFinal(toEncrypt.getBytes());
  
      return encrypted;
   }
  
   public static String decrypt(byte[] toDecrypt, String key) throws Exception {
      // create a binary key from the argument key (seed)
      SecureRandom sr = new SecureRandom(key.getBytes());
      KeyGenerator kg = KeyGenerator.getInstance(algorithm);
      kg.init(sr);
      SecretKey sk = kg.generateKey();
  
      // do the decryption with that key
      Cipher cipher = Cipher.getInstance(algorithm);
      cipher.init(Cipher.DECRYPT_MODE, sk);
      byte[] decrypted = cipher.doFinal(toDecrypt);
  
      return new String(decrypted);
   }
   
   public static String printbyte(byte[] bytetxt){
        String txt = "";
        int i;
        
        for(i=0;i<bytetxt.length-1;i++) txt = txt+bytetxt[i]+" ";
        txt = txt+bytetxt[i];
        return txt;
    }
}
