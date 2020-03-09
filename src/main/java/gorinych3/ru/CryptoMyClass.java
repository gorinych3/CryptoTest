package gorinych3.ru;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import java.security.*;

public class CryptoMyClass {

    public void cryptoSimpleMethod() {
        String code = "ЕСКЕУГЬГМХИФЯ Е УЛП";
        for (char symbol : code.toCharArray()) {
            if (symbol != ' ') {
                symbol = (char) (symbol - 3);
            }
            System.out.print(symbol);
        }
    }

    public void getProvidersJCA(){
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            System.out.println(p.getName());
        }
    }

    public void hashSimpleMethod(){
        try {
            MessageDigest digester = MessageDigest.getInstance("SHA-512");
            byte[] input = "Secret string".getBytes();
            //Перед выполнением метода digest опишем добавление "соли":
                byte[] salt = new byte[16];
                SecureRandom.getInstanceStrong().nextBytes(salt);
                digester.update(salt);
            //
            byte[] digest = digester.digest(input);
            System.out.println(DatatypeConverter.printHexBinary(digest));
            //без соли = 1A26DF58A12F62025520A878D5B2C614F4AB2C7E7646EE164CE1A78EAC444B6A76CA2D374EC9D058BBCBC22A4700E7A07C500EF4D64BF8EB875FBC8AC186FE45
            //с солью =  67A64776BF232FAD8386374A14554C0BFF9A9FD6AB0374398BF4C862F9F66E6463F70229DD2E1A86E3325845C0BB4E1B66BC84DA207CD83EB8A2B9782651BD44
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * algorithm/mode/padding
     * Алгоритм: тут смотрим в стандартных именах для "Cipher (Encryption) Algorithms". Рекомендуется использовать AES.
     * Режим: режим шифрования. Например: ECB или CBC (об этом мы поговорим чуть дальше)
     * Отступ/разбивка: каждый блок данных шифруется отдельно. Данный параметр определяет, какой объём данных считать за 1 блок.
     *
     * Для примера, возьмём следующую трансформацию: "AES/ECB/PKCS5Padding".
     * То есть алгоритм шифрования — AES, режим шифрования ECB (сокращение для Electronic Codebook),
     * размер блока - PKCS5Padding. PKCS5Padding говорит, что размер одного блока - 2 байта (16 бит).
     */
    public void symmetricKeyCryptography() throws Exception {
        String text = "secret!!secret!!secret!!secret!!";
        // Generate new key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);  //нужно 256
        Key key = keygen.generateKey();
        // Encrypt with key
        String transformation = "AES/ECB/PKCS5Padding";
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(text.getBytes());
        System.out.println(DatatypeConverter.printHexBinary(encrypted));
        // Decrypt with key
        cipher.init(Cipher.DECRYPT_MODE, key);
        String result = new String(cipher.doFinal(encrypted));
        System.out.println(result);
        //691DC601EBBC1E1C9ED2FD9AD2BACF1A691DC601EBBC1E1C9ED2FD9AD2BACF1AD08752B876EB55823C46D6F07221A7F6
    }

    public void cipherBlockChaining() throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        //Security.setProperty("crypto.policy", "unlimited");
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] rnd = new byte[16];
        random.nextBytes(rnd);
        IvParameterSpec ivSpec = new IvParameterSpec(rnd);
        // Prepare key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        Key key = keygen.generateKey();
        // CBC
        String text = "secret!!secret!!secret!!secret!!";
        String transformation = "AES/CBC/PKCS5Padding";
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] enc = cipher.doFinal(text.getBytes());
        System.out.println(DatatypeConverter.printHexBinary(enc));
        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        String result = new String(cipher.doFinal(enc));
        System.out.println(result);
    }
}
