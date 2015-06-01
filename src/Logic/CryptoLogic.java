package Logic;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoLogic
{
	// Secure random algo+prov
	private static final String RANDOM_ALGO = "SHA1PRNG";
	private static final String RANDOM_PROV = "SUN";
		
    // Cipher algo+prov 
	private static final String CIPHER_ALGO = "AES/CBC/PKCS5Padding";
	private static final String CIPHER_PROV = "SunJCE";

	// Asymmetric encrypt algo+prov
	private static final String KEY_ENCRYPT_ALGO = "RSA";
	private static final String KEY_ENCRYPT_PROV = "SunJCE";
	
	// Key algo+prov
	private static final String KEY_ALGO = "AES";
	private static final String KEY_PROV= "SunJCE";

	// Signature algo+prov
	private static final String SIGNATURE_ALGO = "MD5withRSA";
	private static final String SIGNATURE_PROV = "SunJSSE";

	// Message digest algo+prov
	private static final String DIGEST_ALGO = "MD5";
	private static final String DIGEST_PROV = "SUN";
    
    // field
    private CryptoConfiguration m_ConfigurationFile;
    private String              m_KeyStoreAlias;
    private String              m_KeyStorePassword;
    private String              m_KeyStoreFilePath;
    private KeyPair             m_keystoreKeyPair;
    private Certificate         m_Certificate;
    
    /**
     * ctor
     * 
     * @param keyStore
     * @param keyStoreAlias
     * @param keyStorePassword
     */
    public CryptoLogic(String keyStorePath, String keyStoreAlias,
            String keyStorePassword)
    {
        m_ConfigurationFile = new CryptoConfiguration();
        m_KeyStoreFilePath = keyStorePath;
        m_KeyStoreAlias = keyStoreAlias;
        m_KeyStorePassword = keyStorePassword;
    }
    
    /**
     * get keys and certificate from key store
     * 
     * @throws Exception
     */
    private void getKeysFromKeyStore() throws Exception
    {
        // Load the KeyStore and get the signing key and certificate
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(m_KeyStoreFilePath),
                m_KeyStorePassword.toCharArray());
        
        Key key = keystore.getKey(m_KeyStoreAlias,
                m_KeyStorePassword.toCharArray());
        if (key instanceof PrivateKey)
        {
            // Get certificate of public key
            m_Certificate = keystore.getCertificate(m_KeyStoreAlias);
            
            // Get public key
            PublicKey publicKey = m_Certificate.getPublicKey();
            
            // Return a key pair
            m_keystoreKeyPair = new KeyPair(publicKey, (PrivateKey) key);
        }
    }
    
    /**
     * Encrypt method: - get the public and private keys from key store -
     * calculate the DS for the text - save configuration file next to encrypt
     * file
     * 
     * @param pathBaseText
     * @param pathEncryptFile
     * @throws Exception
     */
    public void Encrypt(String pathBaseText, String pathEncryptFile)
            throws Exception
    {
        getKeysFromKeyStore();
        
        calculateSignature(pathBaseText);
        
        encryptFile(pathBaseText, pathEncryptFile);
        
        saveConfiguratin(pathBaseText);
        
    }
    
    /**
     * Serialized Crypto configuration
     * 
     * @param fileName
     * @throws FileNotFoundException
     */
    private void saveConfiguratin(String fileName) throws FileNotFoundException
    {
        Path path = Paths.get(fileName);
        String configPath = Paths.get(path.getParent().toString(),
                "ConfigXML.xml").toString();
        
        XMLEncoder encoder = new XMLEncoder(new FileOutputStream(configPath));
        encoder.writeObject(m_ConfigurationFile);
        encoder.close();
    }
    
    /**
     * encrypt the file
     * 
     * @param pathBaseText
     * @param pathEncryptFile
     * @throws Exception
     */
    private void encryptFile(String pathBaseText, String pathEncryptFile)
            throws Exception
    {
        
        File inputFile = new File(pathBaseText);
        File outputFile = new File(pathEncryptFile);
        // Creating IV
        SecureRandom random = SecureRandom.getInstance(RANDOM_ALGO, RANDOM_PROV);
        byte[] seed = random.generateSeed(16);
        IvParameterSpec iv = new IvParameterSpec(seed);
        
        m_ConfigurationFile.setIV(iv.getIV());
        
        // create random key
        Key secretKey;
        KeyGenerator keyGen = KeyGenerator.getInstance(KEY_ALGO, KEY_PROV);
        keyGen.init(random);
        secretKey = keyGen.generateKey();
        
        // create cipher
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO, CIPHER_PROV);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        
        // encrypt
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(
                outputStream, cipher);
        
        byte[] block = new byte[8];
        int i;
        while ((i = inputStream.read(block)) != -1)
        {
            cipherOutputStream.write(block, 0, i);
        }
        
        cipherOutputStream.close();
        outputStream.close();
        inputStream.close();
        
        // encrypt key
        encryptKeyAndRestore(secretKey);
    }
    
    /**
     * encrypt the gen key and restore the key in config file
     * 
     * @param secretKey
     * @throws Exception
     */
    private void encryptKeyAndRestore(Key secretKey) throws Exception
    {
        // cipher
        Cipher cipherKey = Cipher.getInstance(KEY_ENCRYPT_ALGO, KEY_ENCRYPT_PROV);
        cipherKey.init(Cipher.ENCRYPT_MODE, m_keystoreKeyPair.getPublic());
        
        byte[] signEnc = secretKey.getEncoded();
        System.out.print("" + signEnc.toString());
        byte[] secretKeyEnc = cipherKey.doFinal(secretKey.getEncoded());
        
        m_ConfigurationFile.setAesKey(secretKeyEnc);
    }
    
    /**
     * calculate digital signature
     * 
     * @param pathBaseText
     * @throws Exception
     */
    private void calculateSignature(String pathBaseText) throws Exception
    {
        // read text file as byte array
        byte[] inputBytes = Files.readAllBytes(Paths.get(pathBaseText));
        
        //byte[] clearTextBytes = readFileAsBytes(new File(cleartextFile));

		// Digest message
		MessageDigest messageDigest = MessageDigest.getInstance(
				DIGEST_ALGO, DIGEST_PROV);
		messageDigest.update(inputBytes);
		byte[] textDigest = messageDigest.digest();
		
        Signature signature = Signature.getInstance(SIGNATURE_ALGO, SIGNATURE_PROV);
        
        signature.initSign(m_keystoreKeyPair.getPrivate());
        signature.update(textDigest);
        
        m_ConfigurationFile.setDigtalSignaturePublicKey(m_keystoreKeyPair
                .getPublic().getEncoded());
        m_ConfigurationFile.setDigitalSignature(signature.sign());
        
    }
    
    public void Decrypt(String inputFile, String configFile, String resultFile)
            throws Exception
    {
        getKeysFromKeyStore();
        
        deserializedConfiguration(configFile);
        
        checkInputFileValid(inputFile);
        
        decryptFile(inputFile, resultFile);
    }
    
    private void decryptFile(String inputFile, String resultFile)
            throws Exception
    {
        
        // cipher
        Cipher cipherKey = Cipher.getInstance(KEY_ENCRYPT_ALGO, KEY_ENCRYPT_PROV);
        cipherKey.init(Cipher.DECRYPT_MODE, m_keystoreKeyPair.getPrivate());
        
        // byte[] signEnc = cipherKey.doFinal(sigBytes);
        cipherKey.update(m_ConfigurationFile.getAesKey());
        byte[] encodedKey = cipherKey.doFinal();
        
        // create random key
        Key originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length,
                KEY_ALGO);
        
        IvParameterSpec iv = new IvParameterSpec(m_ConfigurationFile.getIV());
        
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO,CIPHER_PROV);
        cipher.init(Cipher.DECRYPT_MODE, originalKey, iv);
        
        FileInputStream inputStream = new FileInputStream(inputFile);
        CipherInputStream cipherInputStream = new CipherInputStream(
                inputStream, cipher);
        
        FileOutputStream outputStream = new FileOutputStream(resultFile);
        
        byte[] block = new byte[8];
        int i;
        while ((i = cipherInputStream.read(block)) != -1)
        {
            outputStream.write(block, 0, i);
        }
        
        cipherInputStream.close();
        outputStream.close();
        inputStream.close();
    }
    
    private void checkInputFileValid(String inputFile) throws Exception
    {
        
        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));
        
        MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO,
				DIGEST_PROV);
		messageDigest.update(inputBytes);
		byte[] textDigest = messageDigest.digest();
		
        Signature signature = Signature.getInstance(SIGNATURE_ALGO,SIGNATURE_PROV);
        
        signature.initVerify(m_Certificate);
        signature.update(textDigest);
        if (signature.verify(m_ConfigurationFile.getDigitalSignature()))
        {
            throw new Exception("File not vaild");
        }
        
    }
    
    /**
     * deserialized configuration
     * 
     * @param configFile
     * @throws Exception
     */
    private void deserializedConfiguration(String configFile) throws Exception
    {
        XMLDecoder decoder = new XMLDecoder(new FileInputStream(configFile));
        m_ConfigurationFile = (CryptoConfiguration) decoder.readObject();
        decoder.close();
    }
    
}
