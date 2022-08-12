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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;

public class Decryptor<T extends Serializable> extends Cryptor {
    Cipher cipher;

    public Decryptor() {
        super();
        try {
            cipher = Cipher.getInstance(Cryptor.CRYPTO_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, Cryptor.getKey());
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

    public T decrypt(String pathToFile) {
        byte[] bytesData = null;
        T retObj = null;
        int bytesRead = 0;
        Path pth = Paths.get(pathToFile);
        File file = new File(pathToFile);
        try (FileInputStream fis = new FileInputStream(file);
             CipherInputStream cis = new CipherInputStream(fis, cipher)) {
            long fileSizeWithPadding = Files.size(pth) + 4096;

            if (fileSizeWithPadding >= Integer.MAX_VALUE){
                System.err.println(Cryptor.INPUT_FILE_TOO_BIG);
                return null;
            }
            bytesData = new byte[(int) fileSizeWithPadding]; // allocate bytes array

            if ((bytesRead = cis.read(bytesData)) == -1) {
                System.err.println(Cryptor.INPUT_FILE_READ_PROBLEM);
                return null;
            } else {
                System.err.println("Cryptor: read " + bytesRead + " bytes from encrypted file");
                try (ByteArrayInputStream bis = new ByteArrayInputStream(bytesData);
                     ObjectInputStream in = new ObjectInputStream(bis)) {
                    retObj = (T) in.readObject();
                }
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
