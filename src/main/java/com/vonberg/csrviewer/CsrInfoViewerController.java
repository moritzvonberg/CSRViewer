package com.vonberg.csrviewer;

import java.io.IOException;

import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.view.RedirectView;



@Controller
public class CsrInfoViewerController {
    final static String FORM_PATH = "/form";
    final static String CSR_POST_PATH = "/submit-csr";

    final static String CSR_FORM_FRAGMENT = "csr-form/fragments/form";
    final static String CSR_SUCCESS_RESPONSE_FRAGMENT = "csr-form/fragments/csr-info-response";
    final static String CSR_FAILURE_RESPONSE_FRAGMENT = "csr-form/fragments/failure-response";

    Logger logger = LoggerFactory.getLogger(CsrInfoViewerController.class);


    @GetMapping("/")
    public RedirectView index() {
        logger.info("served index");
        return new RedirectView(FORM_PATH);
    }

    @GetMapping(FORM_PATH)
    public String form() {
        logger.info("served form");
        return CSR_FORM_FRAGMENT;
    }


    /**
     * Respond to a post request containing a PKCS#10 Certificate Signing Request and add information about its
     * contents to the model used by the templater. Note that the response gets added to the page contents directly
     * via HTMX.
     *
     * @param csrFile a MultiPartFile uploaded from the input form
     * @param model the model that passes data to the templater.
     * @return path to the thymeleaf template of the information contained in the CSR if csrFile is a valid PEM or
     * binary PKCS10 Certificate Signing Request, the path to a failure message fragment otherwise.
     */
    @PostMapping(CSR_POST_PATH)
    public String csrResponse(@RequestParam("csr-file") MultipartFile csrFile, Model model) {
        byte[] bytes;
        try {
            bytes = csrFile.getBytes();
            final var result = PKCS10Parser.parseCSRFromByteArray(bytes);
            model.addAttribute("fileReadSuccess", true)
                    .addAttribute("parseResult", result);
            if (result.state == PKCS10Parser.ParseResultState.SUCCESS) {
                var algorithmNameFinder = new DefaultAlgorithmNameFinder();
                PKCS10CertificationRequest request = result.request;
                model.addAttribute("signatureAlgorithm", algorithmNameFinder.getAlgorithmName(request.getSignatureAlgorithm()))
                        .addAttribute("validationState", PKCS10Parser.tryValidateSignature(request))
                        .addAttribute("subject", request.getSubject())
                        .addAttribute("rDNs", PKCS10Parser.getMappingOfX500NameComponents(request.getSubject()))
                        .addAttribute("subjectAltNames", PKCS10Parser.getAltNames(request));
                // because it's not part of the spec, info about other extensions isn't added
            } else {
                return CSR_FAILURE_RESPONSE_FRAGMENT;
            }
        } catch (IOException e) {
            logger.info("Failed to get content of file {}.", csrFile.getResource().getFilename());
            model.addAttribute("fileReadSuccess", false);
            return CSR_FAILURE_RESPONSE_FRAGMENT;
        }
        return CSR_SUCCESS_RESPONSE_FRAGMENT;
    }


}
