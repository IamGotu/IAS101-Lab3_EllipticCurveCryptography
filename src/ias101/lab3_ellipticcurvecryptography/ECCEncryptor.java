package ias101.lab3_ellipticcurvecryptography;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECCEncryptor {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Load keys
        PrivateKey senderPrivate = ECCKeyLoader.loadPrivateKey("keys/ec_private.pem");
        PublicKey receiverPublic = ECCKeyLoader.loadPublicKey("keys/ec_public.pem");

        // Perform ECDH Key Agreement
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        keyAgreement.init(senderPrivate);
        keyAgreement.doPhase(receiverPublic, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        // Derive AES key from shared secret
        byte[] aesKeyBytes = new byte[16];
        System.arraycopy(sharedSecret, 0, aesKeyBytes, 0, 16);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        
        // Plaintext
        String plaintext = "My name is Mark John Jopia";
        System.out.println("Original Text: " + plaintext);

        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        System.out.println("Encrypted (Base64): " + Base64.getEncoder().encodeToString(ciphertext));

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decrypted = cipher.doFinal(ciphertext);
        System.out.println("Decrypted: " + new String(decrypted));
    }
}