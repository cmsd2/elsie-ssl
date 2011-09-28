package uk.org.elsie.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;

public class KeyStoreTool {
	public static void help() {
		System.err.println("usage: java " + KeyWriter.class.getName() + " <options...>");
		System.err.println("write certificates in base64 encoded pem format,");
		System.err.println("and private keys in base64 encoded pkcs#8 format.");
		System.err.println("use openssl's x509 and pkcs8 commands to view and convert.");
		System.err.println("  -h/-help/--help      this help");
		System.err.println("  -keystore <path>     keystore to read");
		System.err.println("  -password <pass>     keystore password");
		System.err.println("  -key <alias>         key alias to read");
		System.err.println("  -keypassword <pass>  key password if different from keystore password");
		System.err.println("  -cert <alias>        cert alias to read");
		System.err.println("  -out <file>          file to write to");
	}
	
	public static void main(String args[]) {
		String keyStorePath = null;
		String keyAlias = null;
		String certAlias = null;
		String outPath = null;
		String keyPassword = null;
		String keyStorePassword = "";
		OutputStream out;
		InputStream in;
		
		for(int i = 0; i < args.length; i++) {
			if(args[i].equals("-h") || args[i].equals("-help") || args[i].equals("--help")) {
				help();
				return;
			} else if(args[i].equals("-keystore")) {
				i++;
				if(i == args.length) {
					System.err.println("missing option to -keystore");
					help();
					return;
				}
				keyStorePath = args[i];
			} else if(args[i].equals("-key")) {
				i++;
				if(i == args.length) {
					System.err.println("missing option to -key");
					help();
					return;
				}
				keyAlias = args[i];
			} else if(args[i].equals("-cert")) {
				i++;
				if(i == args.length) {
					System.err.println("missing option to -cert");
					help();
					return;
				}
				certAlias = args[i];
			} else if(args[i].equals("-out")) {
				i++;
				if(i == args.length) {
					System.err.println("missing option to -out");
					help();
					return;
				}
				outPath = args[i];
			} else if(args[i].equals("-password")) {
				i++;
				if(i == args.length) {
					System.err.println("missing option to -password");
					help();
					return;
				}
				keyStorePassword = args[i];
			} else if(args[i].equals("-keypassword")) {
				i++;
				if(i == args.length) {
					System.err.println("missing option to -keypassword");
					help();
					return;
				}
				keyPassword = args[i];
			}
		}
		if(keyStorePath == null) {
			System.err.println("missing option -keystore");
			help();
			return;
		}
		if(keyAlias == null && certAlias == null) {
			System.err.println("must provide one of -key or -cert options");
			help();
			return;
		}
		if(keyAlias != null && certAlias != null) {
			System.err.println("must provide only one of -key or -cert options");
			help();
			return;
		}
		try {
			in = new FileInputStream(new File(keyStorePath));
		} catch (IOException e) {
			System.err.println("couldn't open keystore for reading");
			e.printStackTrace();
			return;
		}
		if(outPath == null || outPath.equals("-")) {
			out = System.out;
		} else {
			try {
				out = new FileOutputStream(new File(outPath));
			} catch (IOException e) {
				System.err.println("couldn't open out file for writing");
				e.printStackTrace();
				return;
			}
		}
		
		if(keyPassword == null) {
			keyPassword = keyStorePassword;
		}
		
		try {
			KeyWriter kw = new KeyWriter();
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(in, keyStorePassword.toCharArray());
			if(certAlias != null) {
				Certificate cert = ks.getCertificate(certAlias);
				kw.writeCert(cert, out);
			}
			if(keyAlias != null) {
				Key k = ks.getKey(keyAlias, keyPassword.toCharArray());
				kw.writeKey(k, out);
			}
		} catch (Exception e) {
			System.err.println("error saving key");
			e.printStackTrace();
		}
	}
}
