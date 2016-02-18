package com.tiger.driver;

import com.tiger.keystore.KeyStoreWrapper;

public class Main
{
    public static void main(String[] args) throws Exception
    {
        System.out.println(args[0]);
        KeyStoreWrapper.entry(args);
    }
}
