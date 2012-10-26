/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sanaldiyar.projects.certauth;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.Vector;
import sun.security.pkcs.PKCS10;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AccessDescription;
import sun.security.x509.AlgorithmId;
import sun.security.x509.AuthorityInfoAccessExtension;
import sun.security.x509.AuthorityKeyIdentifierExtension;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CRLDistributionPointsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.DistributionPoint;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.Extension;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.SubjectKeyIdentifierExtension;
import sun.security.x509.URIName;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 *
 * @author kazim
 */
public class CertUtil {

    public enum KeyIdentifierType {

        SUBJECT, AUTHORITY;
    }

    static void setKeyIdentifier(X509CertInfo certInfo, PublicKey publicKey, KeyIdentifierType ki) throws Exception {

        CertificateExtensions extensions = (CertificateExtensions) certInfo.get(CertificateExtensions.NAME);
        if (extensions == null) {
            extensions = new CertificateExtensions();
            certInfo.set(CertificateExtensions.NAME, extensions);
        }

        Extension ex = null;
        String alias = "";
        if (ki == KeyIdentifierType.AUTHORITY) {
            ex = new AuthorityKeyIdentifierExtension(new KeyIdentifier(publicKey), null, null);
            alias = "authority";
        } else {
            ex = new SubjectKeyIdentifierExtension(KeyUtil.calculateKeyIdentifier(publicKey));
            alias = "subject";
        }
        extensions.set(alias, ex);
    }

    public static void setAsServerCertificate(X509CertInfo certInfo) throws Exception {
        try {
            ObjectIdentifier serverOid = ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 1});
            setExtendedKeyUsage(certInfo, serverOid);
        } catch (Exception ex) {
            throw new Exception("Error at setting certificate as server certificate", ex);
        }
    }

    public static void setAsClientCertificate(X509CertInfo certInfo) throws Exception {
        try {
            ObjectIdentifier serverOid = ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 2});
            setExtendedKeyUsage(certInfo, serverOid);
        } catch (Exception ex) {
            throw new Exception("Error at setting certificate as client certificate", ex);
        }
    }

    public static void setAsCodeSigningCertificate(X509CertInfo certInfo) throws Exception {
        try {
            ObjectIdentifier serverOid = ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 3});
            setExtendedKeyUsage(certInfo, serverOid);
        } catch (Exception ex) {
            throw new Exception("Error at setting certificate as code signing certificate", ex);
        }
    }

    public static void setAsEmailCertificate(X509CertInfo certInfo) throws Exception {
        try {
            ObjectIdentifier serverOid = ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 4});
            setExtendedKeyUsage(certInfo, serverOid);
        } catch (Exception ex) {
            throw new Exception("Error at setting certificate as email certificate", ex);
        }
    }

    private static void setExtendedKeyUsage(X509CertInfo certInfo, ObjectIdentifier usage) throws Exception {
        try {

            CertificateExtensions extensions = (CertificateExtensions) certInfo.get(CertificateExtensions.NAME);
            if (extensions == null) {
                extensions = new CertificateExtensions();
                certInfo.set(CertificateExtensions.NAME, extensions);
            }


            BasicConstraintsExtension ca = null;
            try {
                ca = (BasicConstraintsExtension) extensions.get("ca");
            } catch (Exception nex) {
            }
            if (ca == null) {
                ca = new BasicConstraintsExtension(Boolean.TRUE, Boolean.FALSE, 0);
                extensions.set("ca", ca);
            }

            ExtendedKeyUsageExtension keyUsageExtension = null;
            try {
                keyUsageExtension = (ExtendedKeyUsageExtension) extensions.get("keyextusage");
            } catch (Exception nex) {
            }


            if (keyUsageExtension == null) {
                Vector<ObjectIdentifier> objectIdentifiers = new Vector<ObjectIdentifier>();
                objectIdentifiers.add(usage);
                keyUsageExtension = new ExtendedKeyUsageExtension(Boolean.TRUE, objectIdentifiers);
                extensions.set("keyextusage", keyUsageExtension);
            } else {
                Vector<ObjectIdentifier> objectIdentifiers = new Vector<ObjectIdentifier>();
                objectIdentifiers.add(usage);

                for (String susage : keyUsageExtension.getExtendedKeyUsage()) {
                    String[] values = susage.split("\\.");
                    int[] nvalues = new int[values.length];
                    for (int i = 0; i < nvalues.length; i++) {
                        nvalues[i] = Integer.parseInt(values[i]);
                    }
                    ObjectIdentifier uoid = ObjectIdentifier.newInternal(nvalues);
                    objectIdentifiers.add(uoid);
                }


                keyUsageExtension = new ExtendedKeyUsageExtension(Boolean.TRUE, objectIdentifiers);
                extensions.delete("keyextusage");
                extensions.set("keyextusage", keyUsageExtension);
            }

        } catch (Exception ex) {
            throw new Exception("Error at setting extended key usage certificate", ex);
        }
    }

    public static void setCRLInformation(X509CertInfo certInfo, String url) throws Exception {
        try {
            CertificateExtensions extensions = (CertificateExtensions) certInfo.get(CertificateExtensions.NAME);
            if (extensions == null) {
                extensions = new CertificateExtensions();
                certInfo.set(CertificateExtensions.NAME, extensions);
            }
            List<DistributionPoint> crllist = new ArrayList<DistributionPoint>();
            GeneralName gn = new GeneralName(new URIName(url));
            GeneralNames gns = new GeneralNames();
            gns.add(gn);


            crllist.add(new DistributionPoint(gns, null, null));

            CRLDistributionPointsExtension crldpe = new CRLDistributionPointsExtension(crllist);
            extensions.set("crl", crldpe);

        } catch (Exception ex) {
            throw new Exception("Error at setting CRL", ex);
        }
    }

    public static void setAIAInformation(X509CertInfo certInfo, String url) throws Exception {
        try {
            CertificateExtensions extensions = (CertificateExtensions) certInfo.get(CertificateExtensions.NAME);
            if (extensions == null) {
                extensions = new CertificateExtensions();
                certInfo.set(CertificateExtensions.NAME, extensions);
            }
            GeneralName gn = new GeneralName(new URIName(url));
            
            List<AccessDescription> ads=new ArrayList<AccessDescription>();
            
            DerOutputStream tdos=new DerOutputStream();
            tdos.putOID(AccessDescription.Ad_CAISSUERS_Id);
            gn.encode(tdos);
            DerOutputStream dos=new DerOutputStream();
            dos.write(DerValue.tag_Sequence, tdos);
            
            AccessDescription ad=new AccessDescription(new DerValue(dos.toByteArray()));
            
            ads.add(ad);

            AuthorityInfoAccessExtension aiae = new AuthorityInfoAccessExtension(ads);
            extensions.set("aia", aiae);
        } catch (Exception ex) {
            throw new Exception("Error at setting AIA", ex);
        }
    }

    public static X509CertInfo createCertInfo(X500Name subject,
            X500Name issuer, int validForYears, PublicKey publicKey) throws Exception {
        try {
            Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
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

            setKeyIdentifier(certInfo, publicKey, KeyIdentifierType.SUBJECT);

            return certInfo;
        } catch (Exception ex) {
            throw new Exception("Error at cert info creation", ex);
        }
    }

    public static X509CertInfo createCertInfo(PKCS10 request,
            X500Name issuer, int validForYears) throws Exception {
        return createCertInfo(request.getSubjectName(), issuer, validForYears, request.getSubjectPublicKeyInfo());
    }

    public static Certificate createAndSignCertificate(X509CertInfo certInfo,
            KeyPair caKeyPair, long serial) throws Exception {
        try {
            CertificateSerialNumber certificateSerialNumber =
                    new CertificateSerialNumber(BigInteger.valueOf(serial));

            certInfo.set(X509CertInfo.SERIAL_NUMBER, certificateSerialNumber);
            setKeyIdentifier(certInfo, caKeyPair.getPublic(), KeyIdentifierType.AUTHORITY);

            X509CertImpl cert = new X509CertImpl(certInfo);
            cert.sign(caKeyPair.getPrivate(), AlgorithmId.sha1WithRSAEncryption_oid.toString());

            AlgorithmId newAlgorithmId = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);

            certInfo.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, newAlgorithmId);
            cert = new X509CertImpl(certInfo);
            cert.sign(caKeyPair.getPrivate(), AlgorithmId.sha1WithRSAEncryption_oid.toString());
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
