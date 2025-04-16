/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
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

//LogFile imports
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.util.logging.Level;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

//General imports
import java.sql.*;
import java.io.File;
import java.util.ArrayList;
import java.util.Scanner;
import java.security.MessageDigest;

//Exception Handler imports
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;



/**
 * This class holds the internal functions that are responsible for:
 *  1. Loading the passwords into the database
 *  2. Cracking the passwords
 * @author Apache_PHP
 */
public class PasswordCracker {
    //The ArrayList holds the password hashes and is used to fill the database
    private static final ArrayList<String> passwords = new ArrayList();
    /* BufferedWriter will be used throughout the program, so it is a global 
    *  to ensure ease of access
    */
    
    private static BufferedWriter bw;
    
    /**
     * This function sets up the BufferedWriter.
     * In this program, logs are written to LogFile.txt.
     * 
     * To avoid unnecessarily using resources, this function is called then closed
     * multiple times in the program.
     * @throws FileNotFoundException 
     */
    private static void getWriter() throws FileNotFoundException{
        bw = new BufferedWriter(
                new OutputStreamWriter(
                        new FileOutputStream("c://CMPSC222//Module 9 - Hash Functions//LogFile.txt", true)));
    }
    
    /**
     * This function takes the relevant error details, formats the details, and 
     * writes everything to the LogFile. It then closes the Buffered writer to
     * clear up resources
     * @param message
     * @param class_name
     * @throws FileNotFoundException
     * @throws IOException 
     */
    private static void writeToFile(String message, String class_name) throws FileNotFoundException, IOException{
        getWriter();
        bw.append(String.format("""
                                  Name: %s;
                                  Level: %s;
                                  Message: %s;
                                  Exception: %s
                                  Date/Time: %s
                                  """, HashFunctions.class.getName(), Level.SEVERE, message, class_name, LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
        bw.newLine();
        bw.flush();
        bw.close();
    }
    
    /**
     * This function grabs the passwords and loads them into the database
     * @param filename
     * @throws IOException 
     */
    protected static void loadPasswords(String filename) throws IOException{
        try{
           File file = new File(filename);
           Scanner file_reader = new Scanner(file);
           while (file_reader.hasNext()) {
               //Passwords are encrypted before being stored in the global array
               passwords.add(encryptPasswords(file_reader.nextLine()));
           }
       }catch(FileNotFoundException | NoSuchAlgorithmException | UnsupportedEncodingException ex){
           /*
           *  A multi-catch is used as each exception will be ran through the 
           *  same process, just with different values.
           *
           *  These exceptions will be written to the LogFile. The same goes for
           *  all other exceptions in the program
           */
           writeToFile(ex.getMessage(), ex.getClass().toString());
       }finally{
            /* This line is here just to keep the user aware that the LogFile
            *  can be used for troubleshooting.
            */
            System.out.println("Check LogFiles");
       }
    }
    
    /**
     * This function is in charge of uploading the passwords to the database.
     * It iterates through the ArrayList and sends each password through the 
     * addPasswordToDatabase function.
     * 
     * For simplicity, the PreparedStatement is passed to the function along with
     * the actual password
     * @throws IOException 
     */
    protected static void processPasswords() throws IOException{
        String query = "Insert into Passwords(password) values(?);";
        
        try{
            Connection conn = getDBConnection();
            PreparedStatement p_stmt = conn.prepareStatement(query);
            for(String pass: passwords){
                addPasswordToDatabase(pass, p_stmt);
            }
            p_stmt.close();
            conn.close();
        }catch(SQLException ex){
            writeToFile(ex.getMessage(), ex.getClass().toString());
        }
    }
    
    /**
     * In this function, the passwords are encrypted using MD5.
     * The resulting byte array is made into a string via the StringBuilder class
     * @param password
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException 
     */
    protected static String encryptPasswords(String password) throws NoSuchAlgorithmException, UnsupportedEncodingException{
        byte[] encoded_password = password.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(encoded_password);
        StringBuilder sb = new StringBuilder();
        for(byte d_byte: digest){
            sb.append(d_byte);
        }
        return sb.toString();
    }
    
    /**
     * This function holds the internal workings to validate that a user-provided
     * password is within the database.
     * 
     * First the password is encrypted using the MD5 algorithm, then it is passed
     * through a PreparedStatement. The query used here is written to return 
     * the boolean TRUE if the password hash is stored within the database.
     * @param password
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws IOException 
     */
    protected static boolean existPassword(String password) throws NoSuchAlgorithmException, UnsupportedEncodingException, IOException{
        String encoded_password = encryptPasswords(password);
        String query = "Select True as Found From Passwords where password = ?";
        try{
            Connection conn = getDBConnection();
            PreparedStatement p_stmt = conn.prepareStatement(query);
            p_stmt.setString(1, encoded_password);
            ResultSet rs = p_stmt.executeQuery();
            Boolean found = false;
            //If a value is found, then var "found" gets overwritten, otherwise "found" stays false
            while(rs.next()){
                found = rs.getBoolean("Found");
            }
            return found;
        }catch(SQLException ex){
            writeToFile(ex.getMessage(), ex.getClass().toString());
            return false;
        }
    }
    
    /**
     * This function is used in the initial loading of the passwords into the database
     * @param password
     * @param p_stmt
     * @throws IOException 
     */
    protected static void addPasswordToDatabase(String password, PreparedStatement p_stmt) throws IOException{
        try {
            p_stmt.setString(1, password);
            p_stmt.executeUpdate();
        } catch (SQLException ex) {
            writeToFile(ex.getMessage(), ex.getClass().toString());
        }
    }
    
    /**
     * This function obtains the db and jdbc call used throughout the program
     * @return
     * @throws IOException 
     */
    private static Connection getDBConnection() throws IOException{
        String database = "jdbc:ucanaccess://c://CMPSC222//Module 9 - Hash Functions//M9-HashFunctions.accdb";
        try {
            return DriverManager.getConnection(database);
        } catch (SQLException ex) {
            writeToFile(ex.getMessage(), ex.getClass().toString());
            return null;
        }
    }
    
}
