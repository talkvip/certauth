/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sanaldiyar.projects.certauth;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import sun.security.rsa.RSAKeyPairGenerator;
import sun.security.util.DerValue;

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
    
    static byte[] calculateKeyIdentifier(PublicKey publicKey) throws Exception{
        DerValue dv=new DerValue(publicKey.getEncoded());
            if(dv.tag!=DerValue.tag_Sequence){
                throw new Exception("Error at calculate key identifier: key is incorrect");
            }
            DerValue dv2=dv.data.getDerValue();
            if(dv.tag!=DerValue.tag_Sequence){
                throw new Exception("Error at calculate key identifier: key is incorrect");
            }
            DerValue dv3=dv.data.getDerValue();
            if(dv3.tag!=DerValue.tag_BitString){
                throw new Exception("Error at calculate key identifier: key is incorrect");
            }
            byte[] data=dv3.getBitString();
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            return md.digest(data);
    }
}
