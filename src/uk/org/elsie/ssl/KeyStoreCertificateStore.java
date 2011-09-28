package uk.org.elsie.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Set;

public class KeyStoreCertificateStore implements CertificateStore {

	private KeyStore keyStore;
	private Set<String> includedAliases = null;
	
	public KeyStoreCertificateStore() {
	}
	
	public void loadKeyStore(String fileName, char password[]) throws Exception {
		loadKeyStore(new File(fileName), password);
	}
	
	public void loadKeyStore(File file, char password[]) throws Exception {
		loadKeyStore(new FileInputStream(file), password);
	}
	
	public void loadKeyStore(InputStream in, char password[]) throws Exception {
		this.keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		this.keyStore.load(in, password);
	}
	
	public Set<String> getIncludedAliases() {
		return includedAliases;
	}
	
	public void setIncludedAliases(Set<String> includedAliases) {
		this.includedAliases = includedAliases;
	}
	
	@Override
	public Collection<Certificate> getCertificates() throws Exception {
		Enumeration<String> aliases = keyStore.aliases();
		ArrayList<Certificate> certs = new ArrayList<Certificate>();
		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if(includedAliases == null || includedAliases.contains(alias)) {
				Certificate cert = keyStore.getCertificate(alias);
				certs.add(cert);
			}
		}
		return Collections.unmodifiableList(certs);
	}

}
