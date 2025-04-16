/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package com.mycompany.hashfunctions;

/**
 *
 * name: Yakimah Wiley 
 * assignment: M9 - Hash Functions
 * date: 4/14/2025 
 * class: CMPSC222 - Secure Coding
 *
 */

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

/**
 * This program is based on the use of hash functions in the encoding of data
 * stored in database.
 * 
 * The program has two primary functions:
 *  1. Reads the data from a text file, encodes the data, inserts the data into a database
 *  2. Allows a user to check if a given password is contained within the database
 * @author Apache_PHP
 */
public class HashFunctions {

    /**
     * Main function.
     * Responsible for introducing the user to the primary functions of the program
     * and obtaining input from the user for use within the program
     * @param args
     * @throws IOException
     * @throws FileNotFoundException
     * @throws NoSuchAlgorithmException 
     */
    public static void main(String[] args) throws IOException, FileNotFoundException, NoSuchAlgorithmException {
        System.out.println("""
                           Welcome to the Password Cracker program. 
                           Select a menu option from below:""");
        //The exit boolean is used to determine when the user is allowed to exit the program
        Boolean exit = false;
        while(exit == false){
            //Obtains which function (explained above) the user wants to complete
            int selection = selectMenuOption();
            //Based on the user's selection, the program is directed to the correct method
            switch (selection) {
                case 1 -> {
                    loadPasswords();
                    System.out.println("Loading Completed\n");
                }
                case 2 -> {
                    crackPassword();
                }
                case 3 -> {
                    System.out.println("""
                                   Thank you for using our service.
                                   Have a nice day!""");
                    exit = true;
                }
            }
        }
    }
    
    /**
     * This function informs the users of the programs options and requests input
     * based on those options.
     * 
     * It is also in charge of validating that the input provided matched the 
     * integer corresponding to the items in the menu.
     * @return 
     */
    private static int selectMenuOption(){
        System.out.println("""
                           1. Load Passwords to DB
                           2. Crack Password
                           3. Exit\n""");
        Scanner scan = new Scanner(System.in);
        String response = scan.nextLine();
        try{
            //Users are given the option to respond with an integer
            int selection = Integer.parseInt(response);
            if(selection < 1 || selection > 3){
                System.out.println("Invalid input. Select an option from the menu below:\n");
                return selectMenuOption();
            }else{
                return selection;
            }
        }catch(NumberFormatException ex){
            //The user is also given a variety of string input options to determine which function the program is directed to
            switch(response.toLowerCase()){
                case "load", "load passwords", "load passwords to db"->{
                    return 1;
                }
                case "crack", "crack password"->{
                    return 2;
                }
                case "exit", "exit program"->{
                    return 3;
                }
                default->{
                    System.out.println("Invalid input. Select an option from the menu below:\n");
                    return selectMenuOption();
                }
            }
        }
    }
    
    /**
     * This function calls the Password Cracker class to load the passwords
     * in a text file into a specified database
     * @throws IOException 
     */
    private static void loadPasswords() throws IOException {
        String file_name = "c://CMPSC222//Module 9 - Hash Functions//passwords.txt";
        PasswordCracker pc = new PasswordCracker();
        pc.loadPasswords(file_name);
        pc.processPasswords();
    }
    
    /**
     * This function is called to verify if a user provided password is held within the database
     * @throws FileNotFoundException
     * @throws NoSuchAlgorithmException
     * @throws IOException 
     */
    private static void crackPassword() throws FileNotFoundException, NoSuchAlgorithmException, IOException{
        PasswordCracker pc = new PasswordCracker();
        System.out.println("What password would you like to crack?\n");
        String password = getPassword();
        Boolean found = pc.existPassword(password);
        if(found){
            System.out.println("Password Found\n");
        }else{
            System.out.println("Password Not Found\n");
        }
    }
    
    /**
     * This function is in charge of receiving an individual password as input 
     * from the user. 
     * It is used in the crackPassword function. The only criteria here is that 
     * the user provided input is 30 characters of fewer
     * @return 
     */
    private static String getPassword(){
        Scanner scan = new Scanner(System.in);
        String input = scan.nextLine();
        if(input.length() >30){
            System.out.println("""
                               Password must be less than 30 characters long.
                               Enter a new password:\n""");
            return getPassword();
        }
        return input;
    }
}
