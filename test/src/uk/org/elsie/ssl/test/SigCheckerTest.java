package uk.org.elsie.ssl.test;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Callable;

import junit.framework.TestCase;

import uk.org.elsie.ssl.KeyStoreCertificateStore;
import uk.org.elsie.ssl.SigChecker;

public class SigCheckerTest extends TestCase {

	private KeyStoreCertificateStore keyStore;

	public SigCheckerTest() throws Exception {
		keyStore = new KeyStoreCertificateStore();
		keyStore.loadKeyStore(System.getProperty("keystore",
				"test/testkeystore"),
				System.getProperty("keystore.password", "password")
						.toCharArray());
	}

	public static void assertJarWithKeyThrows(final KeyStoreCertificateStore keyStore, String jarName, String alias, Class<?> eclass) {
		final String signedJar = Config.getBuiltJar("a-signed-a.jar");

		Set<String> aliases = new HashSet<String>();
		if(alias != null)
			aliases.add(alias);
		keyStore.setIncludedAliases(aliases);

		Util.assertThrows(eclass, new Callable<Object>() {
			@Override
			public Object call() throws Exception {
				SigChecker checker = new SigChecker(keyStore);

				checker.verify(signedJar);
				
				return null;
			}
		});
	}
	
	public static void assertJarWithKeyPasses(final KeyStoreCertificateStore keyStore, String jarName, String alias)
	{
		String signedJar = Config.getBuiltJar(jarName);

		Set<String> aliases = new HashSet<String>();
		if(alias != null)
			aliases.add(alias);
		keyStore.setIncludedAliases(aliases);

		try {
			SigChecker checker = new SigChecker(keyStore);

			checker.verify(signedJar);
		} catch (Exception e) {
			throw new RuntimeException("shouldn't throw", e);
		}
	}
	
	public void testUnsignedJarWithoutKey() {
		assertJarWithKeyThrows(keyStore, "a.jar", null, SecurityException.class);
	}
	
	public void testUnsignedJarWithKeyA() {
		assertJarWithKeyThrows(keyStore, "a.jar", "testa", SecurityException.class);
	}
	
	public void testUnsignedJarWithKeyB() {
		assertJarWithKeyThrows(keyStore, "a.jar", "testb", SecurityException.class);
	}
	
	public void testSignedAWithoutKey() {
		assertJarWithKeyThrows(keyStore, "a-signed-a.jar", null, SecurityException.class);
	}
	
	public void testSignedAWithKeyA() {
		assertJarWithKeyPasses(keyStore, "a-signed-a.jar", "testa");
	}

	public void testSignedAWithKeyB() {
		assertJarWithKeyThrows(keyStore, "a-signed-a.jar", "testb", SecurityException.class);
	}
	
	public void testSignedAWithKeyCA() {
		assertJarWithKeyThrows(keyStore, "a-signed-a.jar", "testca", SecurityException.class);
	}
	
	public void testSignedBWithoutKey() {
		assertJarWithKeyThrows(keyStore, "a-signed-b.jar", null, SecurityException.class);
	}
	
	public void testSignedBWithKeyA() {
		assertJarWithKeyThrows(keyStore, "a-signed-b.jar", "testa", SecurityException.class);
	}
	
	public void testSignedBWithKeyB() {
		assertJarWithKeyPasses(keyStore, "a-signed-b.jar", "testb");
	}

	public void testSignedBWithKeyCA() {
		assertJarWithKeyPasses(keyStore, "a-signed-b.jar", "testca");
	}
	
	public void testSignedAandBWithoutKey() {
		assertJarWithKeyThrows(keyStore, "a-signed-a-and-b.jar", null, SecurityException.class);
	}
	
	public void testSignedAandBWithKeyA() {
		assertJarWithKeyPasses(keyStore, "a-signed-a-and-b.jar", "testa");
	}
	
	public void testSignedAandBWithKeyB() {
		assertJarWithKeyPasses(keyStore, "a-signed-a-and-b.jar", "testb");
	}

	public void testSignedAandBWithKeyCA() {
		assertJarWithKeyPasses(keyStore, "a-signed-a-and-b.jar", "testca");
	}
	
	public void testSignedAandBthenModifiedWithoutKey() {
		assertJarWithKeyThrows(keyStore, "a-signed-a-and-b-then-modified.jar", null, SecurityException.class);
	}
	
	public void testSignedAandBthenModifiedWithKeyA() {
		assertJarWithKeyThrows(keyStore, "a-signed-a-and-b-then-modified.jar", "testa", SecurityException.class);
	}
	
	public void testSignedAandBthenModifiedWithKeyB() {
		assertJarWithKeyThrows(keyStore, "a-signed-a-and-b-then-modified.jar", "testb", SecurityException.class);
	}

	public void testSignedAandBthenModifiedWithKeyCA() {
		assertJarWithKeyThrows(keyStore, "a-signed-a-and-b-then-modified.jar", "testca", SecurityException.class);
	}
	
	public void testSignedAthenModifiedthenSignedBWithoutKey() {
		assertJarWithKeyThrows(keyStore, "a-signed-a-then-modified-then-signed-b.jar", null, SecurityException.class);
	}
	
	public void testSignedAthenModifiedthenSignedBWithKeyA() {
		assertJarWithKeyThrows(keyStore, "a-signed-a-then-modified-then-signed-b.jar", "testa", SecurityException.class);
	}
	
	public void testSignedAthenModifiedthenSignedBWithKeyB() {
		assertJarWithKeyThrows(keyStore, "a-signed-a-then-modified-then-signed-b.jar", "testb", SecurityException.class);
	}

	public void testSignedAthenModifiedthenSignedBWithKeyCA() {
		assertJarWithKeyThrows(keyStore, "a-signed-a-then-modified-then-signed-b.jar", "testca", SecurityException.class);
	}
	
	public void testSignedAthenExtendedthenSignedBWithoutKey() {
		assertJarWithKeyThrows(keyStore, "a-signed-a-then-extended-then-signed-b.jar", null, SecurityException.class);
	}
	
	public void testSignedAthenExtendedthenSignedBWithKeyA() {
		assertJarWithKeyThrows(keyStore, "a-signed-a-then-extended-then-signed-b.jar", "testa", SecurityException.class);
	}
	
	public void testSignedAthenExtendedthenSignedBWithKeyB() {
		assertJarWithKeyPasses(keyStore, "a-signed-a-then-extended-then-signed-b.jar", "testb");
	}

	public void testSignedAthenExtendedthenSignedBWithKeyCA() {
		assertJarWithKeyPasses(keyStore, "a-signed-a-then-extended-then-signed-b.jar", "testca");
	}
}
