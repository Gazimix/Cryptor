package cryptor;


/**
 * Bad password exception type thrown if the given key word is not up to par
 */
class BadPasswordException extends Exception {
    private static final String BAD_PWD_MSG = "Error: password needs to be either 16 or 32 chars long";
    private static final long serialVersionUID = 1548954898;
    @Override
    public String getMessage() {
        return BAD_PWD_MSG;
    }
}