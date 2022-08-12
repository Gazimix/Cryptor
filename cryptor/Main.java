package cryptor;

import java.util.ArrayList;

/**
 * Testing class, not necessary for using the API.
 */
public class Main {
    static final String PWD = "abcdeabcdeabcdeabcdeabcdeabcdegs";
    static final String WELCOME_MSG = "This is a test simulation to see Cryptor in action. \nAfter running main, one should find text files starting from 1 which should have encrypted content.\nExamine program output to see if decryption has succeeded.";

    public static void main(String args[]) {
        printDelimiter();
        System.out.println(WELCOME_MSG);
        printDelimiter();
        runStrTest();
        printDelimiter();
        runListTest();
        printDelimiter();
    }

    private static void printDelimiter() {
        System.out.println("____________________________________________________________");
    }

    private static void runStrTest() {
        try {
            Encryptor<String> e = new Encryptor<>(PWD);
            e.encrypt(
                    "This is a test, making sure that the encryption works. Examine file 1.txt to see if it is encrypted",
                    "1.txt");
            Decryptor<String> d = new Decryptor<>(PWD);
            String result = d.decrypt("1.txt");
            System.out.println(result);
        } catch (BadPasswordException e) {
            e.printStackTrace();
        }
    }

    private static void runListTest() {
        try {
            ArrayList<Integer> arrList = new ArrayList<>();
            for (int i = 0; i < 1000; ++i) {
                arrList.add(i);
            }
            Encryptor<ArrayList<Integer>> e = new Encryptor<>(PWD);
            e.encrypt(arrList, "2.txt");
            Decryptor<ArrayList<Integer>> d = new Decryptor<>(PWD);
            ArrayList<Integer> result = d.decrypt("2.txt");
            for (int i = 0; i < result.size(); ++i) {
                System.out.print(result.get(i) + "|");
            }
            System.out.print("\n");
        } catch (BadPasswordException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
        }
    }
}
