package cryptor;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

public class Encryptor<T extends Serializable> extends Cryptor {
    Cipher cipher;

    public Encryptor() {
        super();
        try {
            cipher = Cipher.getInstance(Cryptor.CRYPTO_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, Cryptor.getKey());
        } catch (NoSuchAlgorithmException e) {
            System.err.println(Cryptor.NO_ALGORITHM_MSG);
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            System.err.println(Cryptor.NO_PADDING_MSG);
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.err.println(Cryptor.INVALID_KEY_MSG);
            e.printStackTrace();
        }
    }

    public void encrypt(T dataToEncrypt, String pathToFile) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos);) {
            oos.writeObject(dataToEncrypt);
            oos.flush();
            byte[] byteData = bos.toByteArray();

            File file = new File(pathToFile);
            try (FileOutputStream fos = new FileOutputStream(file);
                 CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                cos.write(byteData);
            }
        } catch (IOException e) {
            System.err.println(Cryptor.BAD_IO_MSG);
            e.printStackTrace();
        }
    }
}
