package uk.org.elsie.ssl.test;

import java.io.File;

public class Config
{
	public static String getBuildDir() {
		return System.getProperty("build.dir", "test" + File.separator + "build");
	}
	
	public static String getBuiltJar(String name) {
		return getBuildDir() + File.separator + name;
	}
}