/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sanaldiyar.projects.certauth;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.TimeZone;
import sun.security.x509.AlgorithmId;
import sun.security.x509.AuthorityKeyIdentifierExtension;
import sun.security.x509.CRLExtensions;
import sun.security.x509.CRLNumberExtension;
import sun.security.x509.CRLReasonCodeExtension;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.X509CRLEntryImpl;
import sun.security.x509.X509CRLImpl;

/**
 *
 * @author kazim
 */
public class CRLUtil implements Serializable{

    class CRLData implements Serializable{

        private BigInteger serial;
        private Date revokeDate;
        private int reason;
    }
    private List<CRLData> certificates;
    private BigInteger serial;

    CRLUtil() {
    }

    static CRLUtil getInstance(String dataFile) throws Exception {
        File df = new File(dataFile);
        if (!df.exists()) {
            CRLUtil crlUtil = new CRLUtil();
            crlUtil.serial = BigInteger.ONE;
            crlUtil.certificates = new LinkedList<CRLData>();
            return crlUtil;
        }

        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(new FileInputStream(df));
            CRLUtil crlUtil = (CRLUtil) ois.readObject();
            return crlUtil;
        } catch (Exception ex) {
            try {
                ois.close();
            } catch (Exception tex) {
            }
            throw new Exception("Error while loading CRL", ex);
        }
    }

    static void save(CRLUtil crlUtil, String dataFile) throws Exception {
        ObjectOutputStream oos = null;
        try {
            oos = new ObjectOutputStream(new FileOutputStream(dataFile));
            oos.writeObject(crlUtil);
            oos.close();
        } catch (Exception ex) {
            try {
                oos.close();
            } catch (Exception tex) {
            }
            throw new Exception("Error while saving CRL", ex);
        }
    }

    void incrementSerial() {
        if (this.serial == null) {
            this.serial = BigInteger.ZERO;
        }
        this.serial.add(BigInteger.ONE);
    }

    void addCertificate(Certificate cert, int reason) {
        if (certificates == null) {
            certificates = new LinkedList<CRLData>();
        }
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("GMT"));

        CRLData crlData = new CRLData();
        crlData.serial = ((X509Certificate)cert).getSerialNumber();
        crlData.reason = reason;
        crlData.revokeDate = calendar.getTime();

        certificates.add(crlData);

    }

    X509CRLImpl generateCRL(CAKeyStore caks) throws Exception {
        try {

            Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("GMT"));

            Date begin = calendar.getTime();
            calendar.add(Calendar.MONTH, 1);
            Date end = calendar.getTime();

            CRLExtensions extensions = new CRLExtensions();

            CRLNumberExtension crlne = new CRLNumberExtension(1);
            AuthorityKeyIdentifierExtension akie = new AuthorityKeyIdentifierExtension(new KeyIdentifier(caks.getCAKeyPair().getPublic()), null, null);

            extensions.set("number", crlne);
            extensions.set("authority", akie);

            List<X509CRLEntryImpl> crlEntryList = new ArrayList<X509CRLEntryImpl>();

            for (CRLData crlData : certificates) {

                CRLExtensions reasons = null;
                if (crlData.reason != CRLReasonCodeExtension.UNSPECIFIED) {
                    reasons = new CRLExtensions();
                    CRLReasonCodeExtension rcext = new CRLReasonCodeExtension(crlData.reason);
                    reasons.set("r1", rcext);
                }


                X509CRLEntryImpl crlEntry = new X509CRLEntryImpl(crlData.serial, crlData.revokeDate, reasons);



                crlEntryList.add(crlEntry);

            }

            X509CRLImpl crl = new X509CRLImpl(caks.getCAX500Name(), begin, end, crlEntryList.toArray(new X509CRLEntryImpl[crlEntryList.size()]), extensions);

            crl.sign(caks.getCAPrivateKey(), AlgorithmId.sha1WithRSAEncryption_oid.toString());

            return crl;
        } catch (Exception ex) {
            throw new Exception("Error while generating CRL", ex);
        }
    }
}
