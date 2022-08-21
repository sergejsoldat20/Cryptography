package Model;

import Service.CryptoService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import javax.swing.*;
import java.io.*;
import java.lang.reflect.Array;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class User {

    public static final String RESULT_PATH = "rezultati";
    public static HashMap<String, Integer> userNumberOfGames = new HashMap<>();
    public static ArrayList<User> allUsersList = new ArrayList<>();
    public static ArrayList<User> loggedUser = new ArrayList<>();

    public String username;
    public String password;
    public int result;
    public int numberOfLogins = 0;

    public User(String username, String password){
        this.password = password;
        this.username = username;
        this.result = 0;
    }

    public static boolean checkIfUsernameExist(String username) {
        for (User u : allUsersList) {
            if (u.username.equals(username)) {
                return true;
            }
        }
        return false;
    }

    public static void addNewUser(String username,String password){
        if(!checkIfUsernameExist(username)){
            allUsersList.add(new User(username,password));
            try {
                CryptoService.generateX509Certificate(username,password);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static boolean login(String username, String password) {
        for(User u : allUsersList){
            if(u.password.equals(password) && u.username.equals(username) && u.numberOfLogins < 3){
                u.numberOfLogins++;
                loggedUser.add(u);
                return true;
            }
        }
        try {
            X509Certificate userCertificate = CryptoService.getX509CertificateFromKeyStore(username,password);
            CryptoService.revokeCertificate(userCertificate);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        return false;
    }

    public static void writeResults(User user)  {
        try {
            SecretKey key = CryptoService.decryptRSA(CryptoService.getKeyFromFile("aes.key"),CryptoService.getKeyPair(1));
            byte[] data = readResults();
            String allResults = new String(CryptoService.symmetricDecryption(data,key));
            allResults += user.username + " - " + LocalTime.now().toString() + " - " + user.result + "\n";
            System.out.println(allResults);
            byte[] encryptedData = CryptoService.symmetricEncryption(allResults.getBytes(StandardCharsets.UTF_8),key);
            FileOutputStream os = new FileOutputStream(RESULT_PATH);
            os.write(encryptedData);
            os.flush();
            os.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static byte[] readResults(){
        try{
            FileInputStream fis = new FileInputStream(RESULT_PATH);
            byte[] allBytes = fis.readAllBytes();
            fis.close();
            return allBytes;
        } catch (Exception ex){

        }
        return null;
    }

    public static String getAllResults(){
        try {
            SecretKey key = CryptoService.decryptRSA(CryptoService.getKeyFromFile("aes.key"),CryptoService.getKeyPair(1));
            byte[] data = readResults();
            String allResults = new String(CryptoService.symmetricDecryption(data,key));
            return allResults;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return "";
    }


    public static void logout(){
        loggedUser.remove(0);
    }



    @Override
    public String toString() {
        return "User{" +
                "username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", result=" + result +
                ", numberOfLogins=" + numberOfLogins +
                '}';
    }

    public static void main(String args[]){

        Security.addProvider(new BouncyCastleProvider());
        User user = new User("sergej","ssssss");
        User user1 = new User("aleksa","ssssss");
        System.out.println(getAllResults());

    }

}
