package uk.org.elsie.ssl;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

public class SimpleCertificateStore implements CertificateStore {

	private CertificateFactory certFactory;
	private ArrayList<Certificate> certs;
	
	public CertificateFactory getCertificateFactory()
			throws CertificateException {
		if (this.certFactory == null) {
			this.certFactory = java.security.cert.CertificateFactory
					.getInstance("X.509");
		}
		return this.certFactory;
	}

	public void loadCertificates(InputStream inputStream)
			throws Exception {
		certs = new ArrayList<Certificate>();
		CertificateFactory cf = getCertificateFactory();

		BufferedInputStream bis = new BufferedInputStream(inputStream);

		while (bis.available() > 0) {
			X509Certificate cert = (X509Certificate) cf
					.generateCertificate(bis);
			System.out.println(cert.toString());
			certs.add(cert);
		}
	}
	
	public void loadCertificates(File file) throws Exception {
		FileInputStream fis = new FileInputStream(file);
		loadCertificates(fis);
	}
	
	public void loadCertificates(String fileName) throws Exception {
		loadCertificates(new File(fileName));
	}

	@Override
	public Collection<Certificate> getCertificates() {
		return Collections.unmodifiableList(this.certs);
	}
}
