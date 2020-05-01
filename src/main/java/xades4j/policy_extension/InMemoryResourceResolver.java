package xades4j.policy_extension;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InMemoryResourceResolver extends ResourceResolverSpi
{
	private static final Logger LOGGER = LoggerFactory.getLogger(InMemoryResourceResolver.class);

	private HashMap<URI, byte[]> files = new HashMap<URI, byte[]>();

	public void addFile(URI uri, byte[] data)
	{
		files.put(uri, data);
		LOGGER.debug("Loaded URI [{}] with {} bytes", uri.toString(), data.length);
	}

	public void addFile(String uri, byte[] data) throws URISyntaxException
	{
		addFile(new URI(uri), data);
	}

	@Override
	public XMLSignatureInput engineResolveURI(ResourceResolverContext resourceResolverContext) throws ResourceResolverException
	{
		try
		{
			URI uriNew = getNewURI(resourceResolverContext.uriToResolve, resourceResolverContext.baseUri);
			LOGGER.debug("Loading resource uri: [{}]", uriNew);
			byte[] data = files.get(uriNew);
			if (data == null)
			{
				throw new Exception("File ["+uriNew.toString()+"] not in memory available");
			}
			return new XMLSignatureInput(data);
		}
		catch (Exception e)
		{
			throw new ResourceResolverException(e, resourceResolverContext.uriToResolve, resourceResolverContext.baseUri, "generic.EmptyMessage");
		}
	}

	@Override
	public boolean engineCanResolveURI(ResourceResolverContext context)
	{
		if (context.uriToResolve == null)
		{
			return false;
		}
		else if (!context.uriToResolve.equals("") && context.uriToResolve.charAt(0) != '#' && !context.uriToResolve.startsWith("http:"))
		{
			LOGGER.debug("Return true that this resolver van resolve URI [{}]", context.uriToResolve);
			return true;
		}
		else
		{
			return false;
		}
	}

	private static URI getNewURI(String uri, String baseURI) throws URISyntaxException
	{
		URI newUri = null;
		if (baseURI != null && !"".equals(baseURI))
		{
			newUri = (new URI(baseURI)).resolve(uri);
		}
		else
		{
			newUri = new URI(uri);
		}

		if (newUri.getFragment() != null)
		{
			URI uriNewNoFrag = new URI(newUri.getScheme(), newUri.getSchemeSpecificPart(), (String) null);
			return uriNewNoFrag;
		}
		else
		{
			return newUri;
		}
	}
}
