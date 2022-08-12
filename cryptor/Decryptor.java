package cryptor;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

/**
 * Decryptor class which is used to decrypt previously encrypted objects
 * <T> - the type of object to decrypt. Should be the same as the type
 * that was used to encrypt.
 */
public class Decryptor<T extends Serializable> extends Cryptor {

    static final int BUFFER_PAD = 4096;
    static final int READ_SIZE = 1000;

    /**
     * Class constructor
     * <T> - the type of object to decrypt. Should be the same as the type
     * that was used to encrypt.
     * 
     * @param secretKeyWord the key word which is used to decrypt the file.
     *                      Important to use the same keyword that was used to
     *                      encrypt.
     * @throws BadPasswordException
     */
    public Decryptor(String secretKeyWord) throws BadPasswordException {
        super(secretKeyWord);
        initCipher(Cipher.DECRYPT_MODE);
    }

    /**
     * Call this function with a path to a file to decrypt the bytes from a file of a given object <T>
     * that was encrypted previously to that file.
     * It is imperative that the type we decrypt is the same type we encrypted earlier. 
     * @param pathToFile path to file in which to save encrypted object
     */
    public T decrypt(String pathToFile) {
        byte[] bytesData = null;
        T retObj = null;
        int bytesRead = 0;
        Path pth = Paths.get(pathToFile);
        File file = new File(pathToFile);
        try (FileInputStream fis = new FileInputStream(file);
             CipherInputStream cis = new CipherInputStream(fis, cipher)) {
            int fileSize = (int) Files.size(pth);
            long fileSizeWithPadding = fileSize + BUFFER_PAD;

            if (fileSizeWithPadding >= Integer.MAX_VALUE){
                System.err.println(Cryptor.INPUT_FILE_TOO_BIG);
                return null;
            }
            bytesData = new byte[(int) fileSizeWithPadding]; // allocate bytes array
            int cur = 0;
            while ((bytesRead = cis.read(bytesData, cur, READ_SIZE)) != -1){
                cur += bytesRead;
            }
                try (ByteArrayInputStream bis = new ByteArrayInputStream(bytesData);
                     ObjectInputStream in = new ObjectInputStream(bis)) {
                    retObj = (T) in.readObject();
            }
        } catch (IOException e) {
            System.err.println(Cryptor.BAD_IO_MSG);
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            System.err.println(Cryptor.NO_SUCH_CLASS);
            e.printStackTrace();
        }
        return retObj;
    }
}
