package xades4j.policy_extension;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import xades4j.utils.FileSystemDirectoryCertStore;

public class CertificateManager
{
	private static final Logger LOGGER = LoggerFactory.getLogger(CertificateManager.class);

	public static KeyStore buildKeystore(String path, String password)
	{
		FileInputStream is = null;
		try
		{
			is = new FileInputStream(path);
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(is, password.toCharArray());
			LOGGER.info("Key store loaded successfully");
			return keyStore;
		}
		catch (IOException e)
		{
			throw new IllegalStateException("Error while loading key store", e);
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("Error while loading key store", e);
		}
		finally
		{
			try
			{
				if (is != null)
				{
					is.close();
				}
			}
			catch (IOException e)
			{
				LOGGER.warn("Error closing input stream", e);
			}
		}
	}

	public static CertStore buildCertStoreFromFS(String pathToFolder)
	{
		try
		{
			CertStore certStore = new FileSystemDirectoryCertStore(pathToFolder).getStore();
			LOGGER.debug("Loaded [{}] certs for keystore folder: [{}]", certStore.getCertificates(null).size(), pathToFolder);
			return certStore;
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("Failed building cert store for path:" + pathToFolder);
		}
	}

	public static CertStore buildCertStoreFromKeystore(KeyStore keyStore) throws GeneralSecurityException
	{
		List<Certificate> certificates = new ArrayList<Certificate>();

		Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements())
		{
			String alias = aliases.nextElement();
			// Only use non key entries (certificates)
			if (!keyStore.isKeyEntry(alias))
			{
				certificates.add(keyStore.getCertificate(alias));
			}
		}

		CertStoreParameters certStoreParameters = new CollectionCertStoreParameters(certificates);

		return CertStore.getInstance("Collection", certStoreParameters);
	}

}
