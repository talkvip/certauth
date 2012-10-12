/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sanaldiyar.projects.certauth;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Properties;
import javax.crypto.spec.SecretKeySpec;
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
    private final static String NEXT_SERIAL = "next_serial";
    private String password;
    private File path;
    private KeyStore keyStore;
    private long next_serial = 1;

    public CAKeyStore(String path) {
        this.path = new File(path);
    }

    public synchronized long getNextSerial() {
        long val = next_serial;
        next_serial++;
        return val;
    }

    public boolean isLoaded() {
        return keyStore != null;
    }

    public void load() throws Exception {
        keyStore = KeyStore.getInstance("JKS");
        Properties properties = new Properties();
        if (path.exists()) {
            properties.load(new FileInputStream(path));
            password = properties.getProperty(KEY_STORE_PASSWORD);
            try {
                next_serial = Long.valueOf(properties.getProperty(NEXT_SERIAL));
                keyStore.load(new FileInputStream(properties.getProperty(KEY_STORE_PATH)), password.toCharArray());
            } catch (Exception ex) {
                keyStore = null;
                throw new Exception("Error while loading key store", ex);
            }
        } else {
            properties.setProperty(KEY_STORE_PATH, "key.store");
            password="123456";
            properties.setProperty(KEY_STORE_PASSWORD, password);
            next_serial=1;
            properties.setProperty(NEXT_SERIAL, Long.toString(next_serial));
            properties.store(new PrintWriter(path), "");
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream("key.store"), password.toCharArray());
            load();
        }
    }

    public void save() throws Exception {
        try {
            Properties properties = new Properties();
            properties.load(new FileInputStream(path));
            properties.setProperty(NEXT_SERIAL, Long.toString(next_serial));
            properties.store(new PrintWriter(path), "");
            keyStore.store(new FileOutputStream(properties.getProperty(KEY_STORE_PATH)), password.toCharArray());
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

            X509CertInfo caCertInfo = CertUtil.createCertInfo(caName, caName,
                    CA_VALID_YEARS, caKeyPair.getPublic());

            CertificateExtensions extensions = new CertificateExtensions();
            BasicConstraintsExtension ca = new BasicConstraintsExtension(Boolean.TRUE, Boolean.TRUE, -1);
            extensions.set("ca", ca);

            caCertInfo.set(CertificateExtensions.NAME, extensions);

            Certificate cert = CertUtil.createAndSignCertificate(caCertInfo,
                    caKeyPair.getPrivate(), getNextSerial());

            keyStore.setKeyEntry(CA_PRIVATE_KEY_CERTIFICATE_ALIAS, caKeyPair.getPrivate(), password.toCharArray(),
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
}
