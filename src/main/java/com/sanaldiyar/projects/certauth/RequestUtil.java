/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sanaldiyar.projects.certauth;

import java.io.File;
import java.io.FileInputStream;
import sun.misc.BASE64Decoder;
import sun.security.pkcs.PKCS10;

/**
 *
 * @author kazim
 */
public class RequestUtil {
    public static PKCS10 getCertificateRequest(String fname) throws Exception{
        try {        
            File f=new File(fname);
            byte[] data=new byte[(int)f.length()];
            FileInputStream fis=new FileInputStream(f);
            fis.read(data);
            fis.close();
            
            PKCS10 pkcs10=null;
            try{
             pkcs10=new PKCS10(data);
            } catch (Exception ex){
                String s=new String(data);
                s=s.trim();
                if(s.startsWith("-----BEGIN CERTIFICATE REQUEST-----") && s.endsWith("-----END CERTIFICATE REQUEST-----")){
                    s=s.replace("-----BEGIN CERTIFICATE REQUEST-----", "");
                    s=s.replace("-----END CERTIFICATE REQUEST-----", "");
                    s=s.trim();
                    BASE64Decoder decoder=new BASE64Decoder();
                    byte[] decodeBuffer = decoder.decodeBuffer(s);
                    pkcs10=new PKCS10(decodeBuffer);
                }
            }
            return pkcs10;
        } catch (Exception ex) {
            throw  new Exception("Error while reading request",ex);
        }
    }
}
