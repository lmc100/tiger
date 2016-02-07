package com.tiger.crypto;

import static org.junit.Assert.*;

import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import org.junit.Test;

/**
 * @author Lieming Chen
 *
 */
public class DoubleStrengthPasswordDigestLoginTest
{
    @Test
    public void login() throws Exception
    {
        String user = "Jonathan";
        String password = "buendia";

        PipedInputStream in = new PipedInputStream();
        PipedOutputStream out = new PipedOutputStream(in);

        DoubleStrengthPasswordDigestLogin.ProtectedClient client = new DoubleStrengthPasswordDigestLogin.ProtectedClient();
        client.sendAuthentication(user, password, out);

        // simulate server
        DoubleStrengthPasswordDigestLogin.ProtectedServer server = new DoubleStrengthPasswordDigestLogin.ProtectedServer();

        boolean result = server.authenticate(in);
        assertTrue(result);
        if (result)
        {
            System.out.println("Client logged in.");
        }
        else
        {
            System.out.println("Client failed to log in.");
        }

        out.close();
        in.close();
    }
}
