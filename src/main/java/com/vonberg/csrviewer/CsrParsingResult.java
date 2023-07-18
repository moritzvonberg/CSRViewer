package com.vonberg.csrviewer;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class CsrParsingResult {
    final PKCS10Parser.ParseResultState state;
    final PKCS10CertificationRequest request;

    public CsrParsingResult(PKCS10Parser.ParseResultState state) {
        this(state, null);
    }

    public CsrParsingResult(PKCS10Parser.ParseResultState state, PKCS10CertificationRequest request) {
        if (request == null && state == PKCS10Parser.ParseResultState.SUCCESS) {
            throw new IllegalArgumentException("CSRParsingResult SUCCESS must be instantiated with the result of successfully parsing the request.");
        }
        this.state = state;
        this.request = request;
    }
}
