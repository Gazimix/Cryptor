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

public class Decryptor<T extends Serializable> extends Cryptor {

    public Decryptor() {
        super();
        initCipher(Cipher.DECRYPT_MODE);
    }

    public Decryptor(String pwd) {
        super(pwd);
        initCipher(Cipher.DECRYPT_MODE);
    }

    public T decrypt(String pathToFile) {
        byte[] bytesData = null;
        T retObj = null;
        int bytesRead = 0;
        Path pth = Paths.get(pathToFile);
        File file = new File(pathToFile);
        try (FileInputStream fis = new FileInputStream(file);
             CipherInputStream cis = new CipherInputStream(fis, cipher)) {
            int fileSize = (int) Files.size(pth);
            long fileSizeWithPadding = Files.size(pth) + 4096;

            if (fileSizeWithPadding >= Integer.MAX_VALUE){
                System.err.println(Cryptor.INPUT_FILE_TOO_BIG);
                return null;
            }
            bytesData = new byte[(int) fileSizeWithPadding]; // allocate bytes array
            int cur = 0;
            while ((bytesRead = cis.read(bytesData, cur, 48)) != -1){
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
