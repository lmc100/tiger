package com.tiger.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;
import java.util.Properties;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

/**
 * A simple key store wrapper to read or write passphrase from/to the store. This is used to
 * load tenant credentials from a keystore file. The alias used in the key store is tenant id.
 * The passphrase is the combination of username and password and is stored in {@code
 * KeyStore.SecretKeyEntry}.
 * <p>
 *
 * Note that if the key store is generated using "keytool -importpassword", the key password
 * should use the same password as that used for the {@code keystore}.
 *
 * If user changes the keystore password using "keytool" later, the existing store will not
 * work properly. Instead, user needs to create a new store using new password.
 * <p>
 *
 * To use the class to create entries, follow these steps:
 *
 * <ol>
 * <li>Create an instance of {@code KeyStoreWrapper}</li>
 * <li>Call makeNewKeyStoreEntry to add tenant credentials.</li>
 * <li>Call saveStore to write to a key store file.</li>
 * </ol>
 *
 */
@Slf4j
public class KeyStoreWrapper
{
    private static final String KEYSTORE_TYPE= "JCEKS";

    private static final String KEY_ALGORITHM= "PBE";

    /** The key store */
    @Getter(AccessLevel.PACKAGE)
    private final KeyStore keyStore;

    /** The password for the key store */
    private final char[] keyStorePassword;

    /**
     * Creates an instance of {@code KeyStoreWrapper}.
     *
     * @param keyStoreLocation the keystore location
     * @param keyStorePassword the keystore password
     */
    public KeyStoreWrapper(final String keyStoreLocation, final char[] keyStorePassword)
    {
        if (keyStorePassword == null || keyStorePassword.length < 6)
        {
            throw new IllegalArgumentException(
                "Keystore password must be at least 6 characters");
        }

        this.keyStorePassword = keyStorePassword.clone();
        keyStore = loadKeyStore(keyStoreLocation);
    }

    /**
     * Creates a passphrase entry in key store identified by tenant id. The tenant id is used as
     * key alias in the store. The passphrase is the combination of username and password and saved
     * in {@code KeyStore.SecretKeyEntry}.
     *
     * @param tenantId the tenant ID in UUID format.
     * @param username the username.
     * @param password the password.
     */
    void makeNewKeyStoreEntry(
        @NonNull String tenantId,
        @NonNull String username,
        @NonNull char[] password)
    {
        try
        {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_ALGORITHM);

            char[] user = username.toCharArray();
            char[] userPassword = new char[user.length + password.length + 1];

            System.arraycopy(user, 0, userPassword, 0, user.length);
            userPassword[user.length] = ':';
            System.arraycopy(password, 0, userPassword, user.length + 1, password.length);

            PBEKeySpec pbeKeySpec = new PBEKeySpec(userPassword);
            SecretKey generatedSecret = factory.generateSecret(pbeKeySpec);

            KeyStore.SecretKeyEntry keyEntry =
                new KeyStore.SecretKeyEntry(generatedSecret);

            KeyStore.PasswordProtection passwordProtection =
                new KeyStore.PasswordProtection(keyStorePassword);
            keyStore.setEntry(tenantId, keyEntry, passwordProtection);
        }
        catch (
            NoSuchAlgorithmException |
            InvalidKeySpecException |
            KeyStoreException e)
        {
            String message = String.format("Failed to create entry for: %s", tenantId);
            throw new IllegalStateException(message, e);
        }
    }

    /**
     * Loads tenant credentials from key store to properties.
     *
     * @return properties to contain tenant credentials.
     */
    public Properties loadTenantCredentials()
    {
        Properties userData = new Properties();

        try
        {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_ALGORITHM);

            KeyStore.PasswordProtection passwordProtection =
                new KeyStore.PasswordProtection(keyStorePassword);

            Enumeration<String> en = keyStore.aliases();
            while (en.hasMoreElements())
            {
                String alias = en.nextElement();
                KeyStore.Entry entry = keyStore.getEntry(alias, passwordProtection);

                if (entry instanceof KeyStore.SecretKeyEntry)
                {
                    KeyStore.SecretKeyEntry skEntry = (KeyStore.SecretKeyEntry) entry;
                    PBEKeySpec keySpec =
                        (PBEKeySpec) factory.getKeySpec(skEntry.getSecretKey(), PBEKeySpec.class);

                    String userPassword = new String(keySpec.getPassword());
                    userData.put(alias,  userPassword);
                }
                else
                {
                    log.warn("{} is not an instanceof of SecretKeyEntry.", alias);
                }
            }

            return userData;
        }
        catch (
            InvalidKeySpecException |
            NoSuchAlgorithmException |
            KeyStoreException |
            UnrecoverableEntryException e)
        {
            throw new IllegalStateException("Error in getting tenant credentials.", e);
        }
    }

    /**
     * Writes key store to a file.
     *
     * @param keyStoreLocation the file location
     */
    void saveStore(@NonNull String keyStoreLocation)
    {
        try (OutputStream fos = new FileOutputStream(keyStoreLocation))
        {
            keyStore.store(fos, keyStorePassword);
        }
        catch (
            IOException |
            NoSuchAlgorithmException |
            KeyStoreException |
            CertificateException e)
        {
            throw new IllegalStateException(
                "Failed to save keystore: " + keyStoreLocation,
                e);
        }
    }

    /**
     * Creates a key store. If a key store file already exists, loads data from
     * it. Otherwise, returns an empty store.
     *
     * @return a key store.
     */
    private KeyStore loadKeyStore(String keyStoreLocation)
    {
        try
        {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            if (keyStoreLocation == null)
            {
                ks.load(null, keyStorePassword);
            }
            else
            {
                File file = new File(keyStoreLocation);
                try (FileInputStream inStream = new FileInputStream(file))
                {
                    ks.load(inStream, keyStorePassword);
                }
            }

            return ks;
        }
        catch (
           KeyStoreException |
           IOException |
           CertificateException |
           NoSuchAlgorithmException e)
        {
            throw new IllegalStateException(
                "Failed to load keystore: " + keyStoreLocation,
                e);
        }
    }

    public static void entry(String[] args) throws Exception
    {
        if (args.length < 2)
        {
            System.out.println("Usage: KeyStroeWrapper file_path, password");
            System.exit(1);
        }

        String storeLocation = args[0];
        String storePassword = args[1];
        KeyStoreWrapper keyStoreWrapper = new KeyStoreWrapper(storeLocation, storePassword.toCharArray());
        Properties tenantCredentials = keyStoreWrapper.loadTenantCredentials();
        tenantCredentials.list(System.out);
    }
}
