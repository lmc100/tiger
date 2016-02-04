package com.tiger.crypto;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Message digests produce a small "fingerprint" of a larger set of data.
 *
 * Steps: 1) Getting 2) Feeding 3) digesting
 *
 * @author Lieming Chen
 *
 */
public class Protection
{
    public static byte[] makeDigest(String user, String password, long t1,
            double q1) throws NoSuchAlgorithmException
    {
        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(user.getBytes());
        md.update(password.getBytes());
        md.update(makeBytes(t1, q1));
        return md.digest();
    }

    public static byte[] makeDigest(byte[] mush, long t2, double q2)
            throws NoSuchAlgorithmException
    {
        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(mush);
        md.update(makeBytes(t2, q2));
        return md.digest();
    }

    public static byte[] makeBytes(long t, double q)
    {
        try
        {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            DataOutputStream dataOut = new DataOutputStream(byteOut);
            dataOut.writeLong(t);
            dataOut.writeDouble(q);
            return byteOut.toByteArray();
        }
        catch (IOException e)
        {
            return new byte[0];
        }
    }
}
