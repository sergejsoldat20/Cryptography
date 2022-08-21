package Service;

import Model.User;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.SymmetricKeyWrapper;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.cert.*;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import java.awt.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;
import java.sql.Date;
import java.util.Random;
import java.util.Set;


public class CryptoService {

    public static final String SYMMETRIC_ALGORITHM = "AES";
    public static final String CERTS1_PATH = "Priprema/CA1Certs";
    public static final String CERTS2_PATH = "Priprema/CA2Certs";
    public static final String SIGNING_ALGORITHM = "SHA256withRSA";
    public static final String CRL1_PATH = "Priprema/CA1Certs/firstCRL.crl";
    public static final String CRL2_PATH = "Priprema/CA2Certs/secondCRL.crl";
    public static final String ROOT_CA_PATH = "Priprema/rootca.pem";
    public static final String CA_CERT1_PATH = "Priprema/certs/ca1.crt";
    public static final String CA_CERT2_PATH = "Priprema/certs/ca2.crt";
    public static final String RSA_PRIVATE_KEY1_PATH = "Priprema/private/ca1.key";
    public static final String RSA_PRIVATE_KEY2_PATH = "Priprema/private/ca2.key";
    public static final String RSA_PUBLIC_KEY1_PATH = "Priprema/private/ca1_public.pub";
    public static final String RSA_PUBLIC_KEY2_PATH = "Priprema/private/ca2_public.pub";
    public static final String PROVIDER = "BC";
    public static int serialNumber = 04;
    public static final String USER_CERTS = "Priprema/Usercerts";
    public static final Date NOT_AFTER = Date.valueOf("3000-1-1");
    public static final Date NOT_BEFORE = Date.valueOf("2000-1-1");
    public static final String SERIAL_PATH = "serial.txt";



    public static Random random = new Random();




    public static String hashPassword(String passwd) {
        String passwordHash = "unknownpassword";
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(passwd.getBytes());
            passwordHash = new String(messageDigest.digest());

            passwordHash = Base64.getEncoder().encodeToString(passwordHash.getBytes());
        }
        catch(Exception ex) {
            ex.printStackTrace();
        }

        return passwordHash;
    }


    public static X509Certificate readX509Certificate(String certificatePath) throws Exception {

        File path = new File(certificatePath);
        FileInputStream fis = new FileInputStream(path);
        try {
            CertificateFactory servercf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) servercf.generateCertificate(fis);
        } catch (CertificateException e) {
            // We can assume certificates are valid is most cases
            throw new RuntimeException(e);
        } finally {
            fis.close();
        }
    }

    public static byte[] symmetricEncryption(byte[] input, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        byte[] output = null;
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        output = cipher.doFinal(input);
        return output;
    }

    public static byte[] symmetricDecryption(byte[] input, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        byte[] output = null;
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        output = cipher.doFinal(input);
        return output;
    }

    public static KeyPair getKeyPair(int number) throws Exception{
        if(number == 1){
            return new KeyPair(readRSAPublicFromFile(RSA_PUBLIC_KEY1_PATH), readRSAPrivateFromFile(RSA_PRIVATE_KEY1_PATH));
        } else {
            return new KeyPair(readRSAPublicFromFile(RSA_PUBLIC_KEY2_PATH), readRSAPrivateFromFile(RSA_PRIVATE_KEY2_PATH));
        }
    }

    public static PrivateKey readRSAPrivateFromFile(String filename) throws Exception {
        String privateKeyContent = new String(Files.readAllBytes(Paths.get(filename)));
        privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "");

        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));

        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);
        return privKey;
    }

    public static PublicKey readRSAPublicFromFile(String filename) throws Exception {
        String privateKeyContent = new String(Files.readAllBytes(Paths.get(filename)));
        privateKeyContent = privateKeyContent.replaceAll("\\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");

        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
       // PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PublicKey publicKey = kf.generatePublic(keySpec);
        return publicKey;
    }

    public static X509Certificate generateX509Certificate(String name, String password) throws Exception {
        String userCertificatePath = USER_CERTS + File.separator + name + ".p12";
        X509Certificate caCert = null;
        KeyPair caKey;
        boolean certFileFlag;
        X509Certificate rootCertificate = readX509Certificate(ROOT_CA_PATH);
        if(random.nextBoolean()){
            certFileFlag = true;
            caCert = readX509Certificate(CA_CERT1_PATH);
            caKey = getKeyPair(1);
        } else {
            certFileFlag = false;
            caCert = readX509Certificate(CA_CERT2_PATH);
            caKey = getKeyPair(2);
        }

        X500Name owner = new X500Name("CN=" + name);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA","BC");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(caCert,
                BigInteger.valueOf(serialNumber), NOT_BEFORE, NOT_AFTER, owner, keyPair.getPublic());

        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        X509Certificate userCertificate = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caKey.getPrivate())));
        writeSerialNumber(serialNumber);
        serialNumber++;
        saveX509CertificateToKeyStore(userCertificate,name,userCertificatePath,password,rootCertificate,caCert,keyPair);
        return userCertificate;
    }



    public static void saveCertificateToFile(X509Certificate certificate, String filename) throws IOException {
        StringWriter writer = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(certificate);
        pemWriter.flush();
        pemWriter.close();
        BufferedWriter out = new BufferedWriter(new FileWriter(filename));
        out.write(writer.toString());
        out.flush();
        out.close();
        //System.out.println(writer.toString());
    }

    public static void saveCRL(X509CRL crl, String path){
        try{
            FileOutputStream fos = new FileOutputStream(path);
            fos.write(crl.getEncoded());
            fos.flush();
            fos.close();
        } catch(IOException | CRLException ex){
            ex.printStackTrace();
        }
    }

    public static void saveX509CertificateToFile(X509Certificate certificate) {

    }

    public static X509CRL loadCRL(String path){
        X509CRL crl = null;
        try{
            FileInputStream fis = new FileInputStream(path);
            org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory certificateFactory = new org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory();
            crl = (X509CRL) certificateFactory.engineGenerateCRL(fis);
            fis.close();
        }catch (Exception ex){
            ex.printStackTrace();
        }
        return crl;
    }

    public static void createCRL() throws Exception {
        //generisanje prve crl liste
        X509Certificate ca1 = readX509Certificate(CA_CERT1_PATH);
        KeyPair ca1KeyPair = getKeyPair(1);
        X500Name caName = new X500Name(ca1.getSubjectDN().getName());
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(caName, new java.util.Date());
        crlBuilder.setNextUpdate(NOT_AFTER);
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(SIGNING_ALGORITHM);
        contentSignerBuilder.setProvider(PROVIDER);
        X509CRLHolder crlHolder = crlBuilder.build(contentSignerBuilder.build(ca1KeyPair.getPrivate()));
        JcaX509CRLConverter crlConverter = new JcaX509CRLConverter();
        crlConverter.setProvider(PROVIDER);
        X509CRL crl1 = crlConverter.getCRL(crlHolder);
        saveCRL(crl1,CRL1_PATH);
        //generisanje druge crl liste
        X509Certificate ca2 = readX509Certificate(CA_CERT2_PATH);
        KeyPair ca2KeyPair = getKeyPair(2);
        X500Name ca2Name = new X500Name(ca2.getSubjectDN().getName());
        X509v2CRLBuilder crl2Builder = new X509v2CRLBuilder(ca2Name, new java.util.Date());
        crl2Builder.setNextUpdate(NOT_AFTER);
        X509CRLHolder crl2Holder = crlBuilder.build(contentSignerBuilder.build(ca2KeyPair.getPrivate()));
        JcaX509CRLConverter crl2Converter = new JcaX509CRLConverter();
        crl2Converter.setProvider(PROVIDER);
        X509CRL crl2 = crl2Converter.getCRL(crl2Holder);
        saveCRL(crl2,CRL2_PATH);
    }



    public static void revokeCertificate(X509Certificate certificate) throws Exception {
        String crlPath = null;
        String issuer = certificate.getIssuerDN().toString();
        X509Certificate caCertificate = null;
        KeyPair caKeyPair = null;
        X509CRL crl = null;
        if("CN=ca1".equals(issuer)){
            caKeyPair = getKeyPair(1);
            caCertificate = readX509Certificate(CA_CERT1_PATH);
            crl = loadCRL(CRL1_PATH);
            crlPath = CRL1_PATH;
        } else {
            caKeyPair = getKeyPair(2);
            caCertificate = readX509Certificate(CA_CERT2_PATH);
            crl = loadCRL(CRL2_PATH);
            crlPath = CRL2_PATH;
        }

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new X500Name(caCertificate.getSubjectDN().getName()), new java.util.Date());
        crlBuilder.setNextUpdate(new java.util.Date(System.currentTimeMillis() + 86400 * 1000));

        Set<X509CRLEntry> revokedCerts = (Set<X509CRLEntry>) crl.getRevokedCertificates();
        if(revokedCerts != null){
            for(X509CRLEntry cert : revokedCerts) {
                crlBuilder.addCRLEntry(cert.getSerialNumber(), new java.util.Date(), 5);
            }
        }
        crlBuilder.addCRLEntry(certificate.getSerialNumber(), new java.util.Date(), 5);
        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(SIGNING_ALGORITHM);
        jcaContentSignerBuilder.setProvider(PROVIDER);
        X509CRLHolder crlHolder = crlBuilder.build(jcaContentSignerBuilder.build(caKeyPair.getPrivate()));
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        converter.setProvider(PROVIDER);
        crl = converter.getCRL(crlHolder);
        saveCRL(crl,crlPath);
    }

    public static boolean isRevokedCertificate(X509Certificate certificate){
        X509CRL list1 = loadCRL(CRL1_PATH);
        X509CRL list2 = loadCRL(CRL2_PATH);
        BigInteger certificateSerial = certificate.getSerialNumber();
        X509CRLEntry revokedCertificateCRL1 = list1.getRevokedCertificate(certificate.getSerialNumber());
        X509CRLEntry revokedCertificateCRL2 = list2.getRevokedCertificate(certificate.getSerialNumber());
        if(revokedCertificateCRL1 != null || revokedCertificateCRL2 != null){
            return true;
        } else {
            return false;
        }
    }

    public static byte[] encryptRSA(SecretKey secretKey, KeyPair keyPair) throws NoSuchPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("RSA",PROVIDER);
        cipher.init(Cipher.WRAP_MODE, keyPair.getPublic());
        byte[] encryptedData = cipher.wrap(secretKey);
        return encryptedData;
    }

    public static SecretKey decryptRSA(byte[] data, KeyPair keyPair) throws IllegalBlockSizeException, BadPaddingException,
            NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA",PROVIDER);
        cipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());
        SecretKey key =  (SecretKey) cipher.unwrap(data,"AES",Cipher.SECRET_KEY);
        return key;
    }

    public static String saveX509CertificateToKeyStore(X509Certificate certificate, String username, String path, String password, X509Certificate root, X509Certificate caCertificate, KeyPair userKey)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {

        X509Certificate[] chain = {certificate, caCertificate, root};
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        FileOutputStream fos = new FileOutputStream(path);
        keyStore.load(null, password.toCharArray());
        keyStore.setKeyEntry(username,userKey.getPrivate(), password.toCharArray(), chain);
        keyStore.store(fos,password.toCharArray());
        fos.flush();
        fos.close();
        return path;
    }

    public static X509Certificate getX509CertificateFromKeyStore(String username, String password)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        String path = USER_CERTS + File.separator + username + ".p12";
        FileInputStream fis = new FileInputStream(path);
        keyStore.load(fis,password.toCharArray());
        X509Certificate userCertificate = (X509Certificate)keyStore.getCertificate(username);
        return userCertificate;
    }

    public static SecretKey getKeyFromPassword(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), "AES");
        return secret;
    }

    public static byte[] getKeyFromFile(String path){
        try{
            FileInputStream in = new FileInputStream(path);
            byte[] keyBytes = in.readAllBytes();
            return keyBytes;
        } catch (Exception ex){

        }
        return null;
    }

    public static void writeSerialNumber(Integer serial){
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(SERIAL_PATH));
            writer.write(serial.toString());
            writer.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static void main(String args[]) throws Exception {


        Security.addProvider(new BouncyCastleProvider());
        /*X509Certificate cert = generateX509Certificate("dragan","passw");

        saveCertificateToFile(cert,"dragan.crt");

        cert = readX509Certificate("dragan.crt");
        System.out.println(cert);*/

         //createCRL();
        /*X509Certificate cert = generateX509Certificate("sergej","soki");


        X509Certificate cert2 = generateX509Certificate("aleksa","soki");
        System.out.println(isRevokedCertificate(cert) + " -serial number- " + cert.getSerialNumber() + " next serial " + cert2.getSerialNumber());

        revokeCertificate(cert);
        System.out.println(isRevokedCertificate(cert));*/

        /*generateX509Certificate("sergej","sigurnost");
        generateX509Certificate("aleksa","sigurnost");
        generateX509Certificate("dragan","sigurnost");*/
        /*X509Certificate certificate = getX509CertificateFromKeyStore("aleksa","sigurnost");
        System.out.println(certificate);*/




        byte[] data = getKeyFromFile("aes.key");
        SecretKey key = decryptRSA(data,getKeyPair(1));

        byte[] data1 = "ooooooooo zastooo".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = symmetricEncryption(data1,key);

        byte[] decr = symmetricDecryption(encrypted,key);
        System.out.println(new String(decr));
        System.out.println(LocalDateTime.now());

        FileOutputStream fos = new FileOutputStream(User.RESULT_PATH);
        byte[] prazno = "".getBytes(StandardCharsets.UTF_8);
        fos.write(prazno);
        fos.flush();
        fos.close();

    }
}
