/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javaapplication2;


import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs.PKCS9Attributes;
import sun.security.pkcs.SignerInfo;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

/**
 *
 * @author johnpc
 */
public class NewClass {
    public static void main(String[] args) throws Exception {

        byte[] data = "Hello".getBytes();
        X500Name n = new X500Name("cn=Me");

        CertAndKeyGen cakg = new CertAndKeyGen("RSA", "SHA256withRSA");
        cakg.generate(1024);
        X509Certificate cert = cakg.getSelfCertificate(n, 1000);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        PKCS9Attributes authed = new PKCS9Attributes(new PKCS9Attribute[]{
            new PKCS9Attribute(PKCS9Attribute.CONTENT_TYPE_OID, ContentInfo.DATA_OID),
            new PKCS9Attribute(PKCS9Attribute.MESSAGE_DIGEST_OID, md.digest(data)),
        });

        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(cakg.getPrivateKey());
        s.update(authed.getDerEncoding());
        byte[] sig = s.sign();

        SignerInfo signerInfo = new SignerInfo(
                n,
                cert.getSerialNumber(),
              AlgorithmId.get("SHA1"),
                authed,
            AlgorithmId.get("RSA"),               
                sig,
                null
                );

        PKCS7 pkcs7 = new PKCS7(
                new AlgorithmId[] {signerInfo.getDigestAlgorithmId()},
                new ContentInfo(data),
                new X509Certificate[] {cert},
                new SignerInfo[] {signerInfo});

        if (pkcs7.verify(signerInfo, data) == null) {
            throw new Exception("Not verified");
        }
    }
}
