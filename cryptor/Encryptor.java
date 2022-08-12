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

    /**
     * Constructor for the Encryptor class
     * 
     * @param secretKeyWord the secret key with which the encryption will occur
     * @throws BadPasswordException
     */
    public Encryptor(String secretKeyWord) throws BadPasswordException {
        super(secretKeyWord);
        initCipher(Cipher.ENCRYPT_MODE);
    }

    /**
     * Call this function with a serializable object and a path to a file to
     * write the object as encrypted bytes to the file
     * 
     * @param dataToEncrypt serializable object to be encrypted
     * @param pathToFile    path to file in which to save encrypted object
     */
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
