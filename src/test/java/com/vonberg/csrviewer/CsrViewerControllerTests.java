package com.vonberg.csrviewer;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT
)
class CsrViewerControllerTests {

    private MockMvc mockMvc;

    @BeforeEach
    public void setUp(WebApplicationContext context) {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
    }

    @Test
    public void testGetForm() throws Exception {
        var response = mockMvc.perform(get("/form"))
                .andExpect(status().isOk())
                .andExpect(content().contentType("text/html;charset=UTF-8"))
                .andReturn()
                .getResponse()
                .getContentAsString();
        Document document = Jsoup.parse(response);
        assertEquals("/submit-csr", document.select("#csr").attr("hx-post"));
    }

    @Test
    public void testSubmitCsr() throws Exception {
        MockMultipartFile pemUpload = new MockMultipartFile("csr-file", "sample.csr", "application/pkcs10", SampleCsrData.SAMPLE_CSR_WIKIPEDIA.getBytes());
        var response = mockMvc.perform(
                MockMvcRequestBuilders
                        .multipart("/submit-csr")
                        .file(pemUpload)
                        .contentType("multipart/form-data")
                ).andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        var document = Jsoup.parse(response);
        System.out.println(document);
        assertEquals("EN", document.getElementsByAttributeValue("data-testid", "subject-name-value-C").text());
        assertEquals("MD5WITHRSA", document.getElementsByAttributeValue("data-testid", "signature-algorithm").text());
        assertTrue(document.getElementsByAttributeValue("data-testid", "validation-success-notice").size() >= 1);
    }
}
