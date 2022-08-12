package cryptor;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;
import javax.crypto.Cipher;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import javax.crypto.NoSuchPaddingException;

class Cryptor {
    // Private fields:

    // The password should be either 16 or 32 characters long
    private String pwd;
    private SecretKey key = null;
    protected Cipher cipher;

    // Protected constants, should be accessible to inheriting classes:

    protected static final String BAD_IO_MSG = "Error: couldn't open given file";
    protected static final String NO_SUCH_CLASS = "Error: no such class";
    protected static final String INPUT_FILE_TOO_BIG = "Error: input file is too large to read from";
    protected static final String NO_ALGORITHM_MSG = "Error: no such encryption algorithm";
    protected static final String NO_PADDING_MSG = "Error: no such padding exists";
    protected static final String INVALID_KEY_SPEC_MSG = "Error: invalid key spec";
    protected static final String INVALID_KEY_MSG = "Error: invalid key";
    protected static final String INPUT_FILE_READ_PROBLEM = "Error: couldn't read input file";
    protected static final String CRYPTO_ALGO = "AES";


    protected void initCipher(int cipherMode){
        try {
            cipher = Cipher.getInstance(Cryptor.CRYPTO_ALGO);
            cipher.init(cipherMode, getKey());
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

    public Cryptor(){
        this.pwd = "Thisisjustthedefaultpwdchangeit!";
    }

    public Cryptor(String paramPwd){
        this.pwd = paramPwd;
    }

    // Methods:
    protected SecretKey getKey() {
        if (this.key != null) {
            return this.key;
        }
        try {
            SecureRandom sr = null;
            sr = SecureRandom.getInstanceStrong();
            byte[] salt = new byte[16];
            Objects.requireNonNull(sr).nextBytes(salt);
            this.key = new SecretKeySpec(pwd.getBytes(), "AES");
        } catch (NoSuchAlgorithmException e) {
            System.out.println(NO_ALGORITHM_MSG);
            e.printStackTrace();
        }
        return key;
    }
}
