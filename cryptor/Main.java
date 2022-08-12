package cryptor;

import java.util.ArrayList;

import java.util.BitSet;

public class Main {
    public static void main(String args[]){
        printDelimiter();
        runStrTest();
        printDelimiter();
        runListTest();
    }

    private static void printDelimiter(){
        System.out.println("____________________________________________________________");
    }

    private static void runStrTest(){
        Encryptor<String> e = new Encryptor<>();
        Decryptor<String> d = new Decryptor<>();
        String result = d.decrypt("1.txt");
        System.out.println(result);
    }

    private static void runListTest(){
        ArrayList<Integer> arrList = new ArrayList<>();
        for(int i = 0; i < 10; ++i){
            arrList.add(i);
        }
        Encryptor<ArrayList<Integer>> e = new Encryptor<>();
        e.encrypt(arrList, "2.txt");
        Decryptor<ArrayList<Integer>> d = new Decryptor<ArrayList<Integer>>();
        ArrayList<Integer> result = d.decrypt("2.txt");
        for(int i = 0; i < 10; ++i){
            System.out.println(result.get(i));
        }
    }
}
