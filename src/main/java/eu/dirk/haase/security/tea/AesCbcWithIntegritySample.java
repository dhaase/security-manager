package eu.dirk.haase.security.tea;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

public class AesCbcWithIntegritySample {

    public static void main(String ...args) throws GeneralSecurityException, UnsupportedEncodingException {

        AesCbcWithIntegrity.SecretKeys keys = AesCbcWithIntegrity.generateKey();
        AesCbcWithIntegrity.CipherTextIvMac cipherTextIvMac1 = AesCbcWithIntegrity.encryptString("some test", keys);

        //store or send to server
        String cipherTextString = cipherTextIvMac1.toString();
        System.out.println(cipherTextString);

        //Use the constructor to re-create the CipherTextIvMac class from the string:
        AesCbcWithIntegrity.CipherTextIvMac cipherTextIvMac2 = new AesCbcWithIntegrity.CipherTextIvMac(cipherTextString);
        String plainText = AesCbcWithIntegrity.decryptString(cipherTextIvMac2, keys);

        System.out.println(plainText);
    }

}
