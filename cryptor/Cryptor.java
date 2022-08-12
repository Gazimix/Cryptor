package cryptor;

import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import javax.crypto.NoSuchPaddingException;

/**
 * Cryptor class - a prototype for the Encryptor and the Decryptor classes.
 * <T> - the type of object to encrypt. Should be the same as the type
 * that we will decrypt afterwards.
 */
abstract class Cryptor {
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
    protected static final String KEY_ALGO = "AES";

    /**
     * Initializes the Cipher to be used during encryption and decryption.
     * 
     * @param cipherMode usually either Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     */
    protected void initCipher(int cipherMode) {
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

    /**
     * Constructor for the Cryptor abstract class
     * 
     * @param paramPwd the password to be used as a key in cipher operations
     *                 (decrypt \ encrypt)
     * @throws BadPasswordException a bad password exception if the password is not
     *                              up to par
     */
    public Cryptor(String paramPwd) throws BadPasswordException {
        if (paramPwd.length() == 16 || paramPwd.length() == 32) {
            this.pwd = paramPwd;
        } else {
            throw new BadPasswordException();
        }
    }

    // Methods:
    /**
     * If a key exists - return it, else create a new key and return it.
     * 
     * @return Key object to be used in Cipher operations
     */
    protected SecretKey getKey() {
        if (key == null) {
            synchronized (this) {
                if (key == null) {
                    key = new SecretKeySpec(pwd.getBytes(), "AES");
                }
            }
        }
        return key;
    }
}

/**
 * Bad password exception type thrown if the given key word is not up to par
 */
class BadPasswordException extends Exception {
    private static final String BAD_PWD_MSG = "Error: password needs to be either 16 or 32 chars long";

    @Override
    public String getMessage() {
        return BAD_PWD_MSG;
    }
}