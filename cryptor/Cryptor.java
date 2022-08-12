package cryptor;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

class Cryptor {
    // Private constants:
    private static final String CRYPTO_PWD = "ThisIsSomePwd";
    private static final String SHA1_TOKEN = "SOMETHINGsecreSHA1";
    private static SecretKey key = null;

    // Protected constants, should be accessible to inheriting classes:
    protected static final String BAD_IO_MSG = "Error: couldn't open given file";
    protected static final String NO_SUCH_CLASS = "Error: no such class";
    protected static final String INPUT_FILE_TOO_BIG = "Error: input file is too large to read from";
    protected static final String NO_ALGORITHM_MSG = "Error: no such encryption algorithm";
    protected static final String NO_PADDING_MSG = "Error: no such padding exists";
    protected static final String INVALID_KEY_SPEC_MSG = "Error: invalid key spec";
    protected static final String INVALID_KEY_MSG = "Error: invalid key";
    protected static final String INPUT_FILE_READ_PROBLEM = "Error: couldn't read input file";
    protected static final String CRYPTO_ALGO = "AES/CBC/NoPadding";

    // Methods:
    protected static SecretKey getKey() {
        if (key != null) {
            return key;
        }
        try {
            SecureRandom sr = null;
            sr = SecureRandom.getInstanceStrong();
            byte[] salt = new byte[16];
            Objects.requireNonNull(sr).nextBytes(salt);
            PBEKeySpec spec = new PBEKeySpec(CRYPTO_PWD.toCharArray(), salt, 1000, 128 * 8);
            key = SecretKeyFactory.getInstance(SHA1_TOKEN).generateSecret(spec);
        } catch (InvalidKeySpecException e) {
            System.out.println(INVALID_KEY_SPEC_MSG);
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.out.println(NO_ALGORITHM_MSG);
            e.printStackTrace();
        }
        return key;
    }
}
