/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sanaldiyar.projects.certauth;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 *
 * @author kazim
 */
public class CAKeyStore {
    
    public final static String CA_PRIVATE_KEY_CERTIFICATE_ALIAS = "CAPriKeyCert";
    public final static int CA_VALID_YEARS = 5;
    public final static int CA_RSA_KEY_BIT_LENGTH = 4096;
    private String password;
    private File path;
    private KeyStore keyStore;
    
    public CAKeyStore(String path, String password) {
        this.password = password;
        this.path = new File(path);
    }
    
    public boolean isLoaded() {
        return keyStore != null;
    }
    
    public void load() throws Exception {
        keyStore = KeyStore.getInstance("JKS");
        if (path.exists()) {
            try {
                keyStore.load(new FileInputStream(path), password.toCharArray());
            } catch (Exception ex) {
                keyStore = null;
                throw new Exception("Error while loading key store", ex);
            }
        } else {
            try {
                keyStore.load(null, null);
            } catch (Exception ex) {
                keyStore = null;
            }
        }
    }
    
    public void save() throws Exception {
        try {
            keyStore.store(new FileOutputStream(path), password.toCharArray());
        } catch (Exception ex) {
            throw new Exception("Error while saving key store", ex);
        }
    }
    
    public void exportCACertificate(String fname) throws Exception {
        if (!isLoaded()) {
            throw new Exception("Not loaded!");
        }
        Certificate certificate = keyStore.getCertificate(CA_PRIVATE_KEY_CERTIFICATE_ALIAS);
        CertUtil.writeCertificateToFile(fname, certificate);
    }
    
    public PrivateKey getCAPrivateKey() throws Exception {
        if (!isLoaded()) {
            throw new Exception("Not loaded!");
        }
        return (PrivateKey) keyStore.getKey(CA_PRIVATE_KEY_CERTIFICATE_ALIAS, password.toCharArray());
    }
    
    public Certificate getCACertificate() throws Exception {
        if (!isLoaded()) {
            throw new Exception("Not loaded!");
        }
        return keyStore.getCertificate(CA_PRIVATE_KEY_CERTIFICATE_ALIAS);
    }
    
    public String getCADN() throws Exception {
        return ((X509CertImpl) getCACertificate()).getIssuerDN().getName();
    }
    
    public X500Name getCAX500Name() throws Exception {
        return new X500Name(((X509CertImpl) getCACertificate()).getIssuerDN().getName());
    }
    
    public void initCA(String dn) throws Exception {
        if (!isLoaded()) {
            throw new Exception("Not loaded!");
        }
        try {
            
            KeyPair caKeyPair = KeyUtil.generateKey(CA_RSA_KEY_BIT_LENGTH);
            
            X500Name caName = new X500Name(dn);
            
            X509CertInfo caCertInfo = CertUtil.createCertInfo(caName, caName, CA_VALID_YEARS, caKeyPair.getPublic(), 1);
            
            Certificate cert = CertUtil.createAndSignCertificate(caCertInfo, caKeyPair.getPrivate());
            
            keyStore.setKeyEntry(CA_PRIVATE_KEY_CERTIFICATE_ALIAS, caKeyPair.getPrivate(), password.toCharArray(),
                    new Certificate[]{cert});
            
        } catch (Exception ex) {
            throw new Exception("Error while init CA", ex);
        }        
    }
}
