package pl.btc.invoices.model;


import static org.bouncycastle.cms.RecipientId.password;

import org.xml.sax.SAXException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import java.io.File;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import xades4j.XAdES4jException;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider;
import xades4j.utils.XadesProfileResolutionException;

public class Main {

    private static final String FILENAME = "D:\\Gov_api\\invoices\\src\\main\\resources\\InitSessionSignedRequestExample.xml";
    private static final String KEYPATH = "D:\\Gov_api\\invoices\\src\\main\\resources\\keystore.cer";

    public static void main()
        throws ParserConfigurationException, KeyStoreException, IOException, SAXException, XAdES4jException, CertificateException,
        NoSuchAlgorithmException {
        // Instantiate the Factory
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        KeyStoreKeyingDataProvider.SigningCertSelector certSelector = new KeyStoreKeyingDataProvider.SigningCertSelector() {
            @Override
            public X509Certificate selectCertificate(List<X509Certificate> list) {
                return null;
            }
        };
        KeyStoreKeyingDataProvider.KeyStorePasswordProvider keyStorePasswordProvider = new KeyStoreKeyingDataProvider.KeyStorePasswordProvider() {
            @Override
            public char[] getPassword() {
                return new char[0];
            }
        };
        KeyStoreKeyingDataProvider.KeyEntryPasswordProvider directPasswordProvider = new KeyStoreKeyingDataProvider.KeyEntryPasswordProvider() {
            @Override
            public char[] getPassword(String s, X509Certificate x509Certificate) {
                return new char[0];
            }
        };


        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        char[] pwdArray = "password".toCharArray();
        ks.load(null, pwdArray);
        try (FileOutputStream fos = new FileOutputStream("newKeyStoreFileName.jks")) {
            ks.store(fos, pwdArray);
        }


        org.w3c.dom.Document doc = db.parse(new File(FILENAME));
// Define the signing key/certificate
        KeyingDataProvider kp = new FileSystemKeyStoreKeyingDataProvider(
            "pkcs12", KEYPATH,
            certSelector,
            keyStorePasswordProvider,
            directPasswordProvider, true);
// Define the signed object
        DataObjectDesc obj = new DataObjectReference("")
            .withTransform(new EnvelopedSignatureTransform())
            .withDataObjectFormat(new DataObjectFormatProperty("text/xml"));
// Create the signature
        XadesSigner signer = new XadesBesSigningProfile(kp).newSigner();
        signer.sign(new SignedDataObjects(obj), doc.getDocumentElement());

    }

}
