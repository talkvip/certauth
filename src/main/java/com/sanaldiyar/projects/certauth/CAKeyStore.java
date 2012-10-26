/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sanaldiyar.projects.certauth;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateExtensions;
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
    private final static String KEY_STORE_PATH = "keystore.path";
    private final static String KEY_STORE_PASSWORD = "keystore.password";
    private final static String CRL_STORE_PATH = "crlstore.path";
    private final static String NEXT_SERIAL = "next_serial";
    private final static String DEFAULT_KEYSTORE_PASSWORD = "123456";
    private final static String DEFAULT_KEYSTORE_PATH = "key.store";
    private final static String DEFAULT_CRLSTORE_PATH = "crl.store";
    private File path;
    private KeyStore keyStore;

    public CAKeyStore(String path) {
        this.path = new File(path);
    }

    public synchronized long getNextSerial() {
        try {
            long val = Long.valueOf(getPropertyValue(NEXT_SERIAL));
            setPropertyValue(NEXT_SERIAL, Long.toString(++val));
            return val;
        } catch (Exception ex) {
            Logger.getLogger(CAKeyStore.class.getName()).log(Level.SEVERE, null, ex);
        }
        return -1;
    }
    
    private String getPropertyValue(String prop) throws Exception{
        Properties properties = new Properties();
        properties.load(new FileInputStream(path));
        return properties.getProperty(prop);
    }
    
    private void setPropertyValue(String prop,String value) throws Exception{
        Properties properties = new Properties();
        properties.load(new FileInputStream(path));
        properties.setProperty(prop, value);
        properties.store(new FileOutputStream(path), "");
    }

    public boolean isLoaded() {
        return keyStore != null;
    }

    public void load() throws Exception {
        keyStore = KeyStore.getInstance("JKS");
        Properties properties = new Properties();
        if (path.exists()) {
            properties.load(new FileInputStream(path));
            String password = properties.getProperty(KEY_STORE_PASSWORD);
            try {
                keyStore.load(new FileInputStream(properties.getProperty(KEY_STORE_PATH)), password.toCharArray());
            } catch (Exception ex) {
                keyStore = null;
                throw new Exception("Error while loading key store", ex);
            }
        } else {
            properties.setProperty(KEY_STORE_PATH, DEFAULT_KEYSTORE_PATH);
            properties.setProperty(KEY_STORE_PASSWORD, DEFAULT_KEYSTORE_PASSWORD);
            properties.setProperty(NEXT_SERIAL, Long.toString(1));
            properties.store(new PrintWriter(path), "");
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(DEFAULT_KEYSTORE_PATH), DEFAULT_KEYSTORE_PASSWORD.toCharArray());
            load();
        }
    }

    public void changePassword(String newPasswd) throws Exception {
        if (!isLoaded()) {
            throw new Exception("Not loaded!");
        }
        String storePath;
        Properties properties;
        try {
            KeyStore nkeyStore = KeyStore.getInstance("JKS");
            nkeyStore.load(null, null);
            Map<String, String> aliases = listCertificateAliases();
            
            for(String alias : aliases.values()){
                if(keyStore.isCertificateEntry(alias)){
                    nkeyStore.setCertificateEntry(alias, keyStore.getCertificate(alias));
                }
            }

            Key caKey = keyStore.getKey(CA_PRIVATE_KEY_CERTIFICATE_ALIAS, getPropertyValue(KEY_STORE_PASSWORD).toCharArray());
            nkeyStore.setKeyEntry(CA_PRIVATE_KEY_CERTIFICATE_ALIAS, caKey, newPasswd.toCharArray(), new Certificate[]{getCACertificate()});
            properties = new Properties();
            properties.load(new FileInputStream(path));            
            storePath=properties.getProperty(KEY_STORE_PATH);
            nkeyStore.store(new FileOutputStream(storePath + ".tmp"), newPasswd.toCharArray());
            properties.setProperty(KEY_STORE_PASSWORD, newPasswd);
            properties.setProperty(CRL_STORE_PATH, DEFAULT_CRLSTORE_PATH);
            properties.store(new PrintWriter(path.getAbsolutePath()+ ".tmp"), "");
        } catch (Exception ex) {
            throw new Exception("Error while changing password of store", ex);
        }
        File confFile=new File(path.getAbsolutePath() + ".tmp");
        if(confFile.renameTo(path)){
            File storeFile=new File(storePath+ ".tmp");
            if(!storeFile.renameTo(new File(storePath))){
                throw new Exception("Error while changing password of store");
            }
        }
    }

    public void save() throws Exception {
        try {
            keyStore.store(new FileOutputStream(getPropertyValue(KEY_STORE_PATH)), getPropertyValue(KEY_STORE_PASSWORD).toCharArray());
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
        return (PrivateKey) keyStore.getKey(CA_PRIVATE_KEY_CERTIFICATE_ALIAS, getPropertyValue(KEY_STORE_PASSWORD).toCharArray());
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

            X509CertInfo caCertInfo = CertUtil.createCertInfo(caName, caName,
                    CA_VALID_YEARS, caKeyPair.getPublic());

            CertificateExtensions extensions = new CertificateExtensions();
            BasicConstraintsExtension ca = new BasicConstraintsExtension(Boolean.TRUE, Boolean.TRUE, -1);
            extensions.set("ca", ca);

            caCertInfo.set(CertificateExtensions.NAME, extensions);

            Certificate cert = CertUtil.createAndSignCertificate(caCertInfo,
                    caKeyPair, getNextSerial());

            keyStore.setKeyEntry(CA_PRIVATE_KEY_CERTIFICATE_ALIAS, caKeyPair.getPrivate(), getPropertyValue(KEY_STORE_PASSWORD).toCharArray(),
                    new Certificate[]{cert});

        } catch (Exception ex) {
            throw new Exception("Error while init CA", ex);
        }
    }

    public void addCertificateToStore(Certificate cert) throws Exception {
        try {
            keyStore.setCertificateEntry("cert" + ((X509Certificate) cert).getSerialNumber().toString(), cert);
        } catch (Exception ex) {
            throw new Exception("Error adding cert to store", ex);
        }
    }

    public boolean containsCertificate(String dn) throws Exception {
        return listCertificates().contains(dn);
    }

    public List<String> listCertificates() throws Exception {
        if (!isLoaded()) {
            throw new Exception("Not loaded!");
        }
        try {
            List<String> list = new LinkedList<String>();
            Enumeration<String> aliases = keyStore.aliases();
            for (; aliases.hasMoreElements();) {
                String alias = aliases.nextElement();
                X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
                list.add(certificate.getSubjectDN().getName());
            }
            return list;
        } catch (Exception ex) {
            throw new Exception("Error while listing certificate dns", ex);
        }
    }

    private Map<String, String> listCertificateAliases() throws Exception {
        if (!isLoaded()) {
            throw new Exception("Not loaded!");
        }
        try {
            Map<String, String> map = new HashMap<String, String>();
            Enumeration<String> aliases = keyStore.aliases();
            for (; aliases.hasMoreElements();) {
                String alias = aliases.nextElement();
                X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
                map.put(certificate.getSubjectDN().getName(), alias);
            }
            return map;
        } catch (Exception ex) {
            throw new Exception("Error while listing certificate dns", ex);
        }
    }

    public Certificate getCertificate(String dn) throws Exception {
        if (!isLoaded()) {
            throw new Exception("Not loaded!");
        }
        try {
            Map<String, String> certs = listCertificateAliases();
            if (certs.containsKey(dn)) {
                return keyStore.getCertificate(certs.get(dn));
            }
        } catch (Exception ex) {
            throw new Exception("Error at returning certificate", ex);
        }
        return null;
    }
    
    public KeyPair getCAKeyPair() throws Exception{
        KeyPair keyPair=new KeyPair(getCACertificate().getPublicKey(), getCAPrivateKey());
        return keyPair;
    }
    
    public void revokeCertificate(Certificate cert,int reason) throws Exception{
        if (!isLoaded()) {
            throw new Exception("Not loaded!");
        }
        try {
            String alias="cert" + ((X509CertImpl)cert).getSerialNumber();
            if(keyStore.containsAlias(alias)){
                keyStore.deleteEntry(alias);
                CRLUtil crlUtil=CRLUtil.getInstance(getPropertyValue(CRL_STORE_PATH));
                crlUtil.addCertificate(cert, reason);
                CRLUtil.save(crlUtil, getPropertyValue(CRL_STORE_PATH));
            }
        } catch (Exception ex) {
            throw new Exception("Error while revoking certificate",ex);
        }
    }
    
    public X509CRL getCRL() throws Exception{
        try {
            CRLUtil crlUtil=CRLUtil.getInstance(getPropertyValue(CRL_STORE_PATH));
            return crlUtil.generateCRL(this);
        } catch (Exception ex) {
            throw new Exception("Error while getting CRL",ex);
        }
    }
}
