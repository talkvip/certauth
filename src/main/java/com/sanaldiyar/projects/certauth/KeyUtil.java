/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sanaldiyar.projects.certauth;

import java.security.KeyPair;
import java.security.SecureRandom;
import sun.security.rsa.RSAKeyPairGenerator;

/**
 *
 * @author kazim
 */
public class KeyUtil {

    private static final SecureRandom secureRandom = new SecureRandom();

    public static KeyPair generateKey(int bitcnt) {
        RSAKeyPairGenerator rsakpg = new RSAKeyPairGenerator();

        rsakpg.initialize(bitcnt, secureRandom);
        return rsakpg.generateKeyPair();
    }
}
