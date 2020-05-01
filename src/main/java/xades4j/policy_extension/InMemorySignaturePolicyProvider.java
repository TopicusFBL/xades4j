package xades4j.policy_extension;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import xades4j.properties.IdentifierType;
import xades4j.properties.ObjectIdentifier;
import xades4j.providers.SignaturePolicyDocumentProvider;

public class InMemorySignaturePolicyProvider implements SignaturePolicyDocumentProvider
{
	private static final Logger LOGGER = LoggerFactory.getLogger(InMemoryResourceResolver.class);

	private HashMap<String, byte[]> files = new HashMap<String, byte[]>();

	public void addFile(String signaturePolicyId, byte[] data)
	{
		files.put(signaturePolicyId, data);
		LOGGER.debug("Loaded signature policy with id [{}] and [{}] bytes", signaturePolicyId, data.length);
	}

	@Override
	public InputStream getSignaturePolicyDocumentStream(ObjectIdentifier signaturePolicyId)
	{
		// We ignore the type for now
		IdentifierType identifierType = signaturePolicyId.getIdentifierType();
		String identifier = signaturePolicyId.getIdentifier();
		LOGGER.debug("Retrieving signature policy type [{}] and identifier [{}]", identifierType, identifier);
		if (!files.containsKey(identifier))
		{
			LOGGER.warn("Request to retrieve SignaturePolicy type [{}] with unregistered identifier [{}] failed!", identifierType, identifier);
			return null;
		}

		return new ByteArrayInputStream(files.get(identifier));
	}
}

