package com.vonberg.csrviewer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.vonberg.csrviewer.PKCS10Parser.ParseResultState.ERROR;
import static com.vonberg.csrviewer.PKCS10Parser.ParseResultState.SUCCESS;
import static com.vonberg.csrviewer.PKCS10Parser.ValidationResultState.*;


class PKCS10Parser {

    static Logger logger = LoggerFactory.getLogger(PKCS10Parser.class);

    /**
     * Attempt to validate the signature of a certificate signing request, returning the ValidationResultState
     * corresponding the result of the attempt.
     *
     * @param request the certificate signing request whose signature to verify
     * @return VALID if the signature is valid, INVALID_SIGNATURE if not, and other enum values if an error occurs
     * while attempting to validate the signature.
     */
    static ValidationResultState tryValidateSignature(PKCS10CertificationRequest request) {
        try {
            var publicKeyParameter = PublicKeyFactory.createKey(request.getSubjectPublicKeyInfo());

            var verifierProvider = new BcRSAContentVerifierProviderBuilder(
                    new DefaultDigestAlgorithmIdentifierFinder()
            ).build(publicKeyParameter);

            return request.isSignatureValid(verifierProvider) ? VALID : INVALID_SIGNATURE;
        } catch (OperatorCreationException e) {
            logger.error("Unable to get verifier for the CSR.");
            return UNKNOWN_ALGORITHM;
        } catch (PKCSException e) {
            logger.error("Unable to check signature validity, error while verifying.");
            return MALFORMED_SIGNATURE;
        } catch (IOException e) {
            logger.error("Error while decoding the key from the request.");
            return MALFORMED_SIGNATURE;
        }
    }

    /**
     * Create a representation of the contents of the input name for use by the frontend.
     *
     * @param name an X500Name
     * @return a list of LinkedHashMaps mapping the attribute type of each RDN to its corresponding value.
     */
    static Iterable<LinkedHashMap<String, String>> getMappingOfX500NameComponents(X500Name name) {
        List<LinkedHashMap<String, String>> result = new ArrayList<>();
        for (RDN rdn : name.getRDNs()) {
            LinkedHashMap<String, String> typeDescriptorsAndValues = new LinkedHashMap<>();
            for (AttributeTypeAndValue typeAndValue : rdn.getTypesAndValues()) {
                // this is where I would have liked to include the full human-readable name of the OID
                typeDescriptorsAndValues.put(BCStyle.INSTANCE.oidToDisplayName(typeAndValue.getType()), typeAndValue.getValue().toString());
            }
            result.add(typeDescriptorsAndValues);
        }
        return result;
    }

    /**
     * Attempt to parse a byte array as a certificate signing request in either PEM or binary format, returning a
     * CsrParsingResult of the request state and the resulting request if parsing was successful.
     *
     * @param bytes, the byte array to attempt to parse to a certificate signing request
     * @return a CsrParsingResult of State SUCCESS and the request if parsing was successful, a CsrParsingResult
     * containing a different state and no request otherwise
     */
    static CsrParsingResult parseCSRFromByteArray(byte[] bytes) {
        try {
            var parser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(bytes)));
            Object parsingResult = parser.readObject();
            if (parsingResult instanceof PKCS10CertificationRequest request) {
                return new CsrParsingResult(SUCCESS, request);
            }
            // TODO separately catch IOException from this block which would indicate malformed request
            PKCS10CertificationRequest request = new PKCS10CertificationRequest(bytes);
            logger.info("Request successfully parsed.");
            return new CsrParsingResult(SUCCESS, request);

        } catch (IOException e) {
            logger.error("IO Exception while trying to parse CSR.");
            return new CsrParsingResult(ERROR);
        }
    }

    /**
     * Get any alt names in the provided request, if any.
     *
     * @param request the request whose alt names to extract
     * @return an array of alt names contained in the request
     */
    static GeneralName[] getAltNames(PKCS10CertificationRequest request){
        var requestedExtensions = request.getRequestedExtensions();
        if (requestedExtensions == null){
            return new GeneralName[0];
        }
        var altNamesExtension = requestedExtensions.getExtension(Extension.subjectAlternativeName);
        return GeneralNames.getInstance(altNamesExtension.getParsedValue()).getNames();
    }

    public enum ParseResultState {
        SUCCESS, ERROR
    }

    public enum ValidationResultState {
        VALID, INVALID_SIGNATURE, MALFORMED_SIGNATURE, UNKNOWN_ALGORITHM
    }
}
