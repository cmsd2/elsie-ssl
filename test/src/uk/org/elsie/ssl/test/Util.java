package uk.org.elsie.ssl.test;

import java.util.concurrent.Callable;

import junit.framework.Assert;

public class Util
{
	public static <T> T assertThrows(Class<?> c, Callable<T> r) {
		try {
			return r.call();
		} catch (Exception e) {
			if(c.isInstance(e)) {
				return null;
			} else {
				e.printStackTrace();
				Assert.assertEquals("should throw " + c.getName(), c, e.getClass());
			}
		}
		Assert.assertFalse("should throw " + c.getName(), true);
		return null;
	}
}