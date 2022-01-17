package pl.btc.invoices;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.xml.parsers.ParserConfigurationException;

import pl.btc.invoices.model.Main;
import xades4j.XAdES4jException;
import xades4j.utils.XadesProfileResolutionException;

@SpringBootApplication
public class InvoicesApplication {

	public static void main(String[] args)
		throws XAdES4jException, ParserConfigurationException, KeyStoreException, IOException, SAXException, CertificateException,
		NoSuchAlgorithmException {
		SpringApplication.run(InvoicesApplication.class, args);
		Main.main();
	}

}
