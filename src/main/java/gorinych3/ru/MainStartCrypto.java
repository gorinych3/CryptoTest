package gorinych3.ru;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MainStartCrypto {
    public static void main(String[] args) {

        CryptoMyClass cryptoMyClass = new CryptoMyClass();
        //cryptoMyClass.cryptoSimpleMethod();

        //cryptoMyClass.getProvidersJCA();

        //cryptoMyClass.hashSimpleMethod();


//        try {
//            cryptoMyClass.symmetricKeyCryptography();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }


        try {
            cryptoMyClass.cipherBlockChaining();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
