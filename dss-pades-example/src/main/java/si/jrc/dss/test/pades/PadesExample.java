/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package si.jrc.dss.test.pades;

import eu.europa.esig.dss.DSSDocument;
import java.io.IOException;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import java.io.File;
import java.util.Date;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters.SignerPosition;
import eu.europa.esig.dss.token.JKSSignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import java.awt.Color;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;
import org.apache.pdfbox.preflight.PreflightDocument;
import org.apache.pdfbox.preflight.ValidationResult;
import org.apache.pdfbox.preflight.ValidationResult.ValidationError;
import org.apache.pdfbox.preflight.parser.PreflightParser;
import org.apache.pdfbox.preflight.utils.ByteArrayDataSource;

/**
 *
 * @author Joze Rihtarsic
 */
public class PadesExample {

    public static String FILE_TO_BE_SIGNED = "src/main/resources/gridtest.pdf";
    public static String FILE_SIGNED = "target/gridtest_signed.pdf";

    public static String KEYSTORE_FILEPATH = "src/main/resources/keystore.jks";
    public static String KEYSTORE_PASWORD = "test";
    public static String KEYSTORE_TYPE = "JKS";

    public static String SIG_KEY_ALIAS = "sign-test";
    public static String SIG_KEY_PASSWD = "test";
    public static String SIG_IMAGE_FILE = "src/main/resources/test-image.jpg";

    SimpleDateFormat msdf = new SimpleDateFormat("dd. MM. yyyy HH:mm");

    public static void main(String... args) throws IOException {
        System.setProperty("sun.java2d.cmm", "sun.java2d.cmm.kcms.KcmsServiceProvider");
        PadesExample test = new PadesExample();
        System.out.println("Sign test file");
        test.signTestFile(FILE_SIGNED);

        // validate signature
        System.out.println("Test signature");
        test.validateSignedFile(FILE_SIGNED);
        // validate init document
        System.out.println("Validate pdf/a: source file");
        test.validatePDFAStructure(FILE_TO_BE_SIGNED);
        // validate init document
        System.out.println("Validate pdf/a: signed file");
        test.validatePDFAStructure(FILE_SIGNED);

    }

    public void signTestFile(String toFile) throws IOException {

        File fSigned = new File(toFile);

        if (fSigned.exists()) {
            fSigned.delete();
        }

        // -------------------------------
        // document to be signed
        FileDocument documentToSign = new FileDocument(new File(FILE_TO_BE_SIGNED));
        // signature key 
        JKSSignatureToken jksToken = new JKSSignatureToken(KEYSTORE_FILEPATH, KEYSTORE_PASWORD);

        KSPrivateKeyEntry signatureKey = jksToken.getKey(SIG_KEY_ALIAS, SIG_KEY_PASSWD);

        Date signDate = Calendar.getInstance().getTime();
        // -------------------------------
        // create signature parameters
        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signDate);
        signatureParameters.setSigningCertificate(signatureKey.getCertificate());
        signatureParameters.setCertificateChain(signatureKey.getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setLocation("Maribor");
        signatureParameters.setReason("Simple test");
        signatureParameters.setContactInfo("info@test.si");

        // -------------------------------
        // set signature image
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(new FileDocument(new File(SIG_IMAGE_FILE)));
        imageParameters.setxAxis(20);
        imageParameters.setyAxis(20);

        signatureParameters.setSignatureImageParameters(imageParameters);

        // -------------------------------
        // set signature text
        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText(String.format("Subject:%s\nIssuer:%s\nSerial:%s\nDate:%s",
                signatureKey.getCertificate().getSubjectX500Principal().toString(),
                signatureKey.getCertificate().getIssuerX500Principal().toString(),
                signatureKey.getCertificate().getSerialNumber().toString(),
                msdf.format(signDate)));
        textParameters.setTextColor(Color.GREEN);
        textParameters.setSignerNamePosition(SignerPosition.RIGHT);
        imageParameters.setTextParameters(textParameters);

        // create signature service
        DocumentSignatureService<PAdESSignatureParameters> service = new PAdESService(new CommonCertificateVerifier());
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);

        SignatureValue signatureValue = jksToken.sign(dataToSign,
                signatureParameters.getDigestAlgorithm(),
                signatureKey);

        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
        signedDocument.save(fSigned.getAbsolutePath());

    }

    public void validateSignedFile(String file) throws IOException {

        SignedDocumentValidator validator = SignedDocumentValidator
                .fromDocument(new FileDocument(new File(file)));
        validator.setCertificateVerifier(new CommonCertificateVerifier());
        Reports reports = validator.validateDocument();
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        diagnosticData.getAllSignatures().forEach((sig) -> {
            System.out.println("sig : " + sig.getId() + " is valid: "
                    + (diagnosticData.isBLevelTechnicallyValid(sig.getId()) ? "true" : false));
        });

    }

    public boolean validatePDFAStructure(String file) throws IOException {

        DSSDocument doc = new FileDocument(new File(file));

        try (InputStream is = doc.openStream()) {
            PreflightParser parser = new PreflightParser(new ByteArrayDataSource(is));
            parser.parse();
            PreflightDocument preflightDocument = parser.getPreflightDocument();
            preflightDocument.validate();
            ValidationResult result = preflightDocument.getResult();
            List<ValidationError> errorsList = result.getErrorsList();
            errorsList.forEach((validationError) -> {
                System.out.println("validationError: " + validationError.getDetails());
            });
            return result.isValid();
        }
    }

}
