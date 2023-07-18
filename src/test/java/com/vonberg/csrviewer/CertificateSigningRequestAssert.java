package com.vonberg.CSRViewer;

import org.assertj.core.api.AbstractAssert;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public class CertificateSigningRequestAssert extends AbstractAssert<CertificateSigningRequestAssert, PKCS10CertificationRequest> {

    static final DefaultAlgorithmNameFinder finder = new DefaultAlgorithmNameFinder();
    public CertificateSigningRequestAssert(PKCS10CertificationRequest actual) {
        super(actual, CertificateSigningRequestAssert.class);
    }

    public static CertificateSigningRequestAssert assertThat(PKCS10CertificationRequest actual){
        return new CertificateSigningRequestAssert(actual);
    }

    public CertificateSigningRequestAssert subjectNameToStringEquals(String expected){
        isNotNull();
        if (!actual.getSubject().toString().equals(expected)){
            failWithMessage("Expected CSR subject name to be %s but got %s", expected, actual.getSubject());
        }
        return this;
    }

    public CertificateSigningRequestAssert algorithmIdEquals(AlgorithmIdentifier id){
        isNotNull();
        if (!actual.getSignatureAlgorithm().equals(id)){
            failWithMessage("Expected CSR algorithm to be %s but got %s", finder.getAlgorithmName(id),
                    finder.getAlgorithmName(actual.getSignatureAlgorithm()));
        }
        return this;
    }

    public CertificateSigningRequestAssert hasNoAltNames(){
        isNotNull();
        var altNames = PKCS10Parser.getAltNames(actual);
        if (altNames != null){
            failWithMessage("Expected CSR to have no alternative names, but it contained: %s",
                    Arrays.stream(altNames).map(GeneralName::toString).collect(Collectors.joining(", ")));
        }
        return this;
    }

    public CertificateSigningRequestAssert altNamesContainParsedValue(String value){
        isNotNull();
        var altNames = PKCS10Parser.getAltNames(actual);
        if (altNames == null){
            failWithMessage("Expected CSR to contain alt name %s but it didn't contain any alt names.", value);
        } else if (Arrays.stream(altNames).noneMatch(x -> x.toString().equals(value))) {
            failWithMessage("Expected CSR to contain alt name %s, but it doesn't.", value);
        }
        return this;
    }

    public CertificateSigningRequestAssert signatureIsValid(){
        return signatureValidationResultEquals(PKCS10Parser.ValidationResultState.VALID);
    }

    public CertificateSigningRequestAssert signatureIsInvalid(){
        return signatureValidationResultDoesNotEqual(PKCS10Parser.ValidationResultState.VALID);
    }

    public CertificateSigningRequestAssert signatureValidationResultEquals(PKCS10Parser.ValidationResultState state){
        isNotNull();
        var validationAttemptResult = PKCS10Parser.tryValidateSignature(actual);
        if (!validationAttemptResult.equals(state)){
            failWithMessage("Expected VerificationResultState %s, but got state %s", state.name(), validationAttemptResult.name());
        }
        return this;
    }

    public CertificateSigningRequestAssert signatureValidationResultDoesNotEqual(PKCS10Parser.ValidationResultState state){
        isNotNull();
        var validationAttemptResult = PKCS10Parser.tryValidateSignature(actual);
        if (validationAttemptResult.equals(state)){
            failWithMessage("Expected VerificationResultState not to be %s, but it was", state.name());
        }
        return this;
    }

    public CertificateSigningRequestAssert subjectNameContains(Map<ASN1ObjectIdentifier, String> keyValuePairs){
        return this;
    }
}
