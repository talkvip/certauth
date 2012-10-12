/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sanaldiyar.projects.certauth;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.Vector;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 *
 * @author kazim
 */
public class CertUtil {

    public static void setAsServerCertificate(X509CertInfo certInfo) throws Exception {
        try {
            Vector<ObjectIdentifier> objectIdentifiers = new Vector<ObjectIdentifier>();
            ObjectIdentifier serverOid = ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 1});
            objectIdentifiers.add(serverOid);
            ExtendedKeyUsageExtension keyUsageExtension = new ExtendedKeyUsageExtension(Boolean.TRUE, objectIdentifiers);

            CertificateExtensions extensions = (CertificateExtensions) certInfo.get(CertificateExtensions.NAME);
            if (extensions == null) {
                extensions = new CertificateExtensions();
                certInfo.set(CertificateExtensions.NAME, extensions);
            }
            extensions.set("serverusage", keyUsageExtension);
        } catch (Exception ex) {
            throw new Exception("Error at setting certificate as server certificate", ex);
        }
    }
    
    public static X509CertInfo createCertInfo(X500Name subject, 
            X500Name issuer, int validForYears, PublicKey publicKey) throws Exception {
        try {
            Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("Europe/Istanbul"));
            Date from = calendar.getTime();
            calendar.add(Calendar.YEAR, validForYears);
            Date to = calendar.getTime();


            AlgorithmId algorithmId = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);

            CertificateValidity certificateValidity = new CertificateValidity(from, to);
            CertificateAlgorithmId certificateAlgorithmId = new CertificateAlgorithmId(algorithmId);
            
            CertificateIssuerName certificateIssuerName = new CertificateIssuerName(issuer);
            CertificateSubjectName certificateSubjectName = new CertificateSubjectName(subject);
            CertificateVersion certificateVersion = new CertificateVersion(CertificateVersion.V3);
            CertificateX509Key certificateX509Key = new CertificateX509Key(publicKey);


            X509CertInfo certInfo = new X509CertInfo();

            certInfo.set(X509CertInfo.ALGORITHM_ID, certificateAlgorithmId);
            certInfo.set(X509CertInfo.ISSUER, certificateIssuerName);
            certInfo.set(X509CertInfo.KEY, certificateX509Key);
            certInfo.set(X509CertInfo.SUBJECT, certificateSubjectName);
            certInfo.set(X509CertInfo.VALIDITY, certificateValidity);
            certInfo.set(X509CertInfo.VERSION, certificateVersion);

            return certInfo;
        } catch (Exception ex) {
            throw new Exception("Error at cert info creation", ex);
        }
    }

    public static Certificate createAndSignCertificate(X509CertInfo certInfo, 
            PrivateKey privateKey, long serial) throws Exception {
        try {
            CertificateSerialNumber certificateSerialNumber = 
                    new CertificateSerialNumber(BigInteger.valueOf(serial));
            
            certInfo.set(X509CertInfo.SERIAL_NUMBER, certificateSerialNumber);
            
            X509CertImpl cert = new X509CertImpl(certInfo);
            cert.sign(privateKey, AlgorithmId.sha1WithRSAEncryption_oid.toString());

            AlgorithmId newAlgorithmId = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);

            certInfo.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, newAlgorithmId);
            cert = new X509CertImpl(certInfo);
            cert.sign(privateKey, AlgorithmId.sha1WithRSAEncryption_oid.toString());
            return cert;
        } catch (Exception ex) {
            throw new Exception("Error while creating and signig certificate", ex);
        }
    }

    public static CertPath generateCertificateChain(Certificate ca, Certificate cert) throws Exception {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            ArrayList<Certificate> list = new ArrayList<Certificate>();
            list.add(ca);
            list.add(cert);
            CertPath res = certificateFactory.generateCertPath(list);

            return res;
        } catch (Exception ex) {
            throw new Exception("Error while creating cert chain", ex);
        }
    }

    public static void writeCertificateChain(String fname, Certificate ca, Certificate cert) throws Exception {
        try {
            CertPath chain = generateCertificateChain(ca, cert);
            byte[] chain_data = chain.getEncoded("PKCS7");
            String s = new String(chain_data);
            FileOutputStream fos = new FileOutputStream(fname);
            fos.write(chain_data);
            fos.close();
        } catch (Exception ex) {
            throw new Exception("Error at writing cert chain", ex);
        }

    }

    public static void writeCertificateToFile(String fname, Certificate cert) throws Exception {
        try {
            byte[] certData = cert.getEncoded();
            FileOutputStream fos = new FileOutputStream(fname);
            fos.write(certData);
            fos.close();
        } catch (Exception ex) {
            throw new Exception("Error while exporting certificate", ex);
        }
    }
}
