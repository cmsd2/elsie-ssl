package uk.org.elsie.ssl;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class SigChecker {

	private CertificateStore certs;

	public SigChecker(CertificateStore certs) throws Exception {
		this.certs = certs;
	}

	public void verify(String url) throws Exception {
		JarFile jf;

		System.out.println("verifying " + url);
		try {
			jf = new JarFile(url);
		} catch (IOException e) {
			throw new Exception("error opening " + url, e);
		}

		walkJarEntries(jf);
	}

	public void walkJarEntries(JarFile jarFile) throws Exception {
		// Ensure all the entries' signatures verify correctly
		byte[] buffer = new byte[8192];
		Enumeration<JarEntry> entries = jarFile.entries();

		while (entries.hasMoreElements()) {
			JarEntry je = (JarEntry) entries.nextElement();

			// Skip directories.
			if (je.isDirectory())
				continue;

			InputStream is = jarFile.getInputStream(je);

			// Read in each jar entry. A security exception will
			// be thrown if a signature/digest check fails.
			// This will happen if a signature is present but
			// does not match the hash of the content.
			// i.e. the content was modified after signing.
			while ((is.read(buffer, 0, buffer.length)) != -1) {
				// Don't care
			}
			is.close();

			checkSigTrusted(je);
		}

	}

	public X509Certificate[] checkSigTrusted(JarEntry je) throws Exception {
		System.out.println("checking " + je.getName());
		Certificate[] certs = je.getCertificates();
		if ((certs == null) || (certs.length == 0)) {
			if (!je.getName().startsWith("META-INF"))
				throw new SecurityException(
						"The entry is not signed: "
								+ je.getName());
			return null;
		} else {
			// Check whether the file is signed by the expected
			// signer. The jar may be signed by multiple signers.
			// See if one of the signers is in the list of trusted certs.
			int startIndex = 0;
			X509Certificate[] certChain;

			while ((certChain = getAChain(certs, startIndex)) != null) {
				System.out.println("got chain of length " + certChain.length);
				for (int i = 0; i < certChain.length; i++) {
					System.out.println("checking cert " + certChain[i].getSubjectDN().toString());
					if (this.certs.getCertificates().contains(certChain[i])) {
						// Stop since one trusted signer is found.
						return certChain;
					}
				}

				// Proceed to the next chain.
				startIndex += certChain.length;
			}

			// the entry is signed, but not by a certificate that is
			// either directly or indirectly trusted.
			throw new SecurityException(
					"The entry is not signed by a trusted signer: " + je.getName());

		}
	}

	private static X509Certificate[] getAChain(Certificate[] certs,
			int startIndex) {

		if (startIndex > certs.length - 1)
			return null;

		int i;
		// Keep going until the next certificate is not the
		// issuer of this certificate.
		for (i = startIndex; i < certs.length - 1; i++) {
			if (!((X509Certificate) certs[i + 1]).getSubjectDN().equals(
					((X509Certificate) certs[i]).getIssuerDN())) {
				break;
			}
		}

		// Construct and return the found certificate chain.
		int certChainSize = (i - startIndex) + 1;
		X509Certificate[] ret = new X509Certificate[certChainSize];
		for (int j = 0; j < certChainSize; j++) {
			ret[j] = (X509Certificate) certs[startIndex + j];
		}
		return ret;
	}

}