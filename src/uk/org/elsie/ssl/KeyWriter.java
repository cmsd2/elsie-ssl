package uk.org.elsie.ssl;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

public class KeyWriter {
	public void writeCert(Certificate cert, OutputStream out) throws IOException, CertificateEncodingException {
		Writer writer = new OutputStreamWriter(out);
		writeCert(cert, writer);
		writer.close();
	}

	public void writeCert(Certificate cert, Writer writer) throws IOException, CertificateEncodingException {
		byte[] bytes = cert.getEncoded();
		String encoded = Base64.encodeBytes( bytes, Base64.DO_BREAK_LINES );
		writer.write("-----BEGIN CERTIFICATE-----\n");
		writer.write(encoded);
		writer.write("\n-----END CERTIFICATE-----\n");
	}
	
	public void writeKey(Key key, OutputStream out) throws IOException {
		Writer writer = new OutputStreamWriter(out);
		writeKey(key, writer);
		writer.close();
	}
	
	public void writeKey(Key key, Writer writer) throws IOException {
		byte[] bytes = key.getEncoded();
		String encoded = Base64.encodeBytes( bytes, Base64.DO_BREAK_LINES );
		writer.write("-----BEGIN PRIVATE KEY-----\n");
		writer.write(encoded);
		writer.write("\n-----END PRIVATE KEY-----\n");
	}
}
