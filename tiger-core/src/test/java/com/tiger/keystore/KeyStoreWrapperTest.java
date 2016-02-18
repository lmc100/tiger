package com.tiger.keystore;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class KeyStoreWrapperTest
{
    private static String tenantId1 = "0a4fa51c-c040-46a0-a3d0-63ca0e9ae699";

    private static String tenantId2 = "6d081f8d-0871-46a3-8c69-4c7d775f93d9";

    /** The instance to be tested */
    private KeyStoreWrapper keyStoreWrapper;

    private char[] storePassword = "tenants-pwd".toCharArray();

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Before
    public void setup()
    {
        keyStoreWrapper = new KeyStoreWrapper(null, storePassword);
    }

    @Test
    public void loadNonExistingFile()
    {
        String keyStoreLocation = "foo.jseks";
        thrown.expect(IllegalStateException.class);

        thrown.expectMessage(
            allOf(
                containsString("Failed to load keystore:"),
                containsString(keyStoreLocation))
        );

        new KeyStoreWrapper(keyStoreLocation, "foo-123456".toCharArray());
    }

    @Test
    public void passwordIsTooShort()
    {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Keystore password must be at least 6 characters");

        new KeyStoreWrapper(null, "foo".toCharArray());
    }

    @Test
    public void passwordIsNull()
    {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Keystore password must be at least 6 characters");

        new KeyStoreWrapper(null, null);
    }

    @Test
    public void createNewStore() throws Exception
    {
        KeyStoreWrapper keyStoreWrapper = new KeyStoreWrapper(null,
            "foo-123456".toCharArray());
        assertEquals(0, keyStoreWrapper.getKeyStore().size());
    }

    @Test
    public void addNewKeyEntries() throws Exception
    {
        keyStoreWrapper.makeNewKeyStoreEntry(tenantId1, "usr", "pwd".toCharArray());
        keyStoreWrapper.makeNewKeyStoreEntry(tenantId2, "usr@pronto", "bar".toCharArray());
        assertEquals(2, keyStoreWrapper.getKeyStore().size());
    }

    @Test
    public void addDuplicatedKey() throws Exception
    {
        keyStoreWrapper.makeNewKeyStoreEntry(tenantId1, "usr", "pwd".toCharArray());
        keyStoreWrapper.makeNewKeyStoreEntry(tenantId1, "usr", "pwd".toCharArray());
        assertEquals(1, keyStoreWrapper.getKeyStore().size());
    }

    @Test
    public void addNullUser() throws Exception
    {
        thrown.expect(NullPointerException.class);
        keyStoreWrapper.makeNewKeyStoreEntry(tenantId1, null, "pwd".toCharArray());
    }

    @Test
    public void addNullPassword() throws Exception
    {
        thrown.expect(NullPointerException.class);
        keyStoreWrapper.makeNewKeyStoreEntry(tenantId1, "user", null);
    }
}
