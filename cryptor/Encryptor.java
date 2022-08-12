package cryptor;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;

public class Encryptor<T extends Serializable> extends Cryptor {

    public Encryptor() {
        super();
        initCipher(Cipher.ENCRYPT_MODE);

    }

    public Encryptor(String pwd) {
        super(pwd);
        initCipher(Cipher.ENCRYPT_MODE);
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
