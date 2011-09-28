package uk.org.elsie.ssl;

import java.security.cert.Certificate;
import java.util.Collection;

public interface CertificateStore {
	public Collection<Certificate> getCertificates() throws Exception;
}
