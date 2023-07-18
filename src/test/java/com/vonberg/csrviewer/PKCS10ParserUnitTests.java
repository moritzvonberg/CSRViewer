package com.vonberg.csrviewer;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class PKCS10ParserUnitTests {

    private static final DefaultAlgorithmNameFinder finder = new DefaultAlgorithmNameFinder();

    @Test
    void parseCSRFromByteArrayTest() {
        var result = PKCS10Parser.parseCSRFromByteArray("This is not a valid Certificate Signing Request".getBytes());
        assertEquals(result.state, PKCS10Parser.ParseResultState.ERROR);
    }

    @Test
    void parseWikipediaPemTest() {
        // sample PEM from https://en.wikipedia.org/wiki/Certificate_signing_request
        var result = PKCS10Parser.parseCSRFromByteArray(SampleCsrData.SAMPLE_CSR_WIKIPEDIA.getBytes());
        assertEquals(result.state, PKCS10Parser.ParseResultState.SUCCESS);
        assertEquals(finder.getAlgorithmName(result.request.getSignatureAlgorithm()), "MD5WITHRSA");
        assertEquals(result.request.getSubject().toString(), "C=EN,ST=none,L=none,O=Wikipedia,OU=none,CN=*.wikipedia.org,E=none@none.com");
        assertNull(result.request.getRequestedExtensions());
    }

    @Disabled
    @ParameterizedTest
    void buildAndValidateSignature(X500Name subjectName, String signatureAlgorithm) {
        // TODO
    }


}
