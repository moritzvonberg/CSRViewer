package com.vonberg.CSRViewer;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;


public class TestCsrBuilder {

    record KeyPairAndCsrPair(PKCS10CertificationRequest request, KeyPair keyPair) {
        KeyPairAndCsrPair {
            if (request == null || keyPair == null) {
                throw new IllegalArgumentException("Null provided instead of request or keypair!");
            }
        }
        }


    public static KeyPairAndCsrPair buildCSR(X500Name name, String keyAlgorithmId, String signatureAlgorithmId, int keySize, Attribute[] attributes) throws Exception{
        var generator = KeyPairGenerator.getInstance(keyAlgorithmId);
        generator.initialize(keySize, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(name, pair.getPublic());
        for (var attribute: attributes){
            builder.addAttribute(attribute.getAttrType(), attribute.getAttrValues());
        }
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithmId).build(pair.getPrivate());
        return new KeyPairAndCsrPair(builder.build(signer), pair);
    }

}
