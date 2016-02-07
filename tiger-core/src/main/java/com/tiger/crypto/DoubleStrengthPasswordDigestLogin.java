package com.tiger.crypto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

/**
 * Double-Strength Password Login
 *
 * Why is this better than the simpler scheme we outlined earlier? To understand
 * why, think about how you might try to break the protected password scheme.
 * Recall that a message digest is a one-way function; ideally, this means that
 * it's impossible to figure out what input produced a given digest value.[2]
 * Thus, your best bet is to launch a dictionary attack. This means that you try
 * passwords, one at a time, running them through the simple protection
 * algorithm just described and attempting to log in each time. In this process,
 * it's important to consider how much time it takes to test a single password.
 * In the double-strength protection scheme, two digest values must be computed
 * instead of just one, which should double the time required for a dictionary
 * attack.
 *
 * @author Lieming Chen
 *
 */
public class DoubleStrengthPasswordDigestLogin
{
    public static void main(String[] args) throws Exception
    {
        String user = "Jonathan";
        String password = "buendia";

        PipedInputStream in = new PipedInputStream();
        PipedOutputStream out = new PipedOutputStream(in);

        ProtectedClient client = new ProtectedClient();
        client.sendAuthentication(user, password, out);

        // simulate server
        ProtectedServer server = new ProtectedServer();

        if (server.authenticate(in))
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

    static class ProtectedClient
    {
        public void sendAuthentication(String user, String password,
                OutputStream outStream) throws IOException,
                NoSuchAlgorithmException
        {
            DataOutputStream out = new DataOutputStream(outStream);
            long t1 = (new Date()).getTime();
            double q1 = Math.random();
            byte[] protected1 = Protection.makeDigest(user, password, t1, q1);

            // double digest
            long t2 = (new Date()).getTime();
            double q2 = Math.random();
            byte[] protected2 = Protection.makeDigest(protected1, t2, q2);

            out.writeUTF(user);
            out.writeLong(t1);
            out.writeDouble(q1);
            out.writeLong(t2);
            out.writeDouble(q2);
            out.writeInt(protected2.length);
            out.write(protected2);
            out.flush();
        }
    }

    static class ProtectedServer
    {
        public boolean authenticate(InputStream inStream) throws IOException,
                NoSuchAlgorithmException
        {
            DataInputStream in = new DataInputStream(inStream);

            String user = in.readUTF();
            System.out.println(user);

            long t1 = in.readLong();
            double q1 = in.readDouble();
            long t2 = in.readLong();
            double q2 = in.readDouble();
            int length = in.readInt();
            byte[] protected2 = new byte[length];
            in.readFully(protected2);

            String password = lookupPassword(user);

            byte[] local1 = Protection.makeDigest(user, password, t1, q1);
            byte[] local2 = Protection.makeDigest(local1, t2, q2);
            return MessageDigest.isEqual(protected2, local2);
        }

        protected String lookupPassword(String user)
        {
            return "buendia";
        }
    }
}
