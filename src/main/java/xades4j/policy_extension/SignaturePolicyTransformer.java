package xades4j.policy_extension;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Set;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.google.inject.internal.ImmutableSet;

import xades4j.algorithms.Algorithm;
import xades4j.algorithms.XPath2FilterTransform;
import xades4j.properties.ObjectIdentifier;
import xades4j.providers.SignaturePolicyDocumentProvider;

public class SignaturePolicyTransformer
{
	private static final Logger LOGGER = LoggerFactory.getLogger(SignaturePolicyTransformer.class);

	static final Set<String> canonicalizeTypes = ImmutableSet.of("http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
			"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
			"http://www.w3.org/2001/10/xml-exc-c14n#",
			"http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
			"http://www.w3.org/2006/12/xml-c14n11",
			"http://www.w3.org/2006/12/xml-c14n11#WithComments",
			"http://santuario.apache.org/c14n/physical");

	public InputStream processPolicyForIdentifier(SignaturePolicyDocumentProvider signaturePolicyDocumentProvider, ObjectIdentifier policyIdentifier, Collection<Algorithm> transforms) throws SignaturePolicyTransformException
	{
		InputStream policyDocumentStream = getPolicyDocumentStream(signaturePolicyDocumentProvider, policyIdentifier);
		if(policyDocumentStream == null)
		{
			LOGGER.warn("No policy document found for identifier [{}] by provider [{}]", policyIdentifier, signaturePolicyDocumentProvider.getClass());
			throw new SignaturePolicyTransformException(policyIdentifier, null);
		}
		Object policyDocument = null;
		try
		{
			policyDocument = parseSignaturePolicyDocument(policyDocumentStream);
		}
		catch (IOException exception)
		{
			throw new SignaturePolicyTransformException(policyIdentifier, exception);
		}

		if (policyDocument instanceof Document)
		{
			Document signaturePolicyDocument = processSignatures(policyIdentifier, (Document) policyDocument, transforms);
			byte[] newDocumentAsBytes = documentToByte(signaturePolicyDocument);
			return new ByteArrayInputStream(newDocumentAsBytes);
		}
		else if (policyDocument instanceof InputStream)
		{
			return (InputStream) policyDocument;
		}
		else
		{
			throw new SignaturePolicyTransformException(policyIdentifier, null);
		}
	}

	public InputStream getPolicyDocumentStream(SignaturePolicyDocumentProvider signaturePolicyDocumentProvider, ObjectIdentifier policyIdentifier)
	{
		return signaturePolicyDocumentProvider.getSignaturePolicyDocumentStream(policyIdentifier);
	}

	public Object parseSignaturePolicyDocument(InputStream policyDocumentStream) throws IOException
	{
		try
		{
			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
			documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			documentBuilderFactory.setNamespaceAware(true);
			DocumentBuilder builder = documentBuilderFactory.newDocumentBuilder();
			return builder.parse(policyDocumentStream);
		}
		catch (SAXException exception)
		{
			return handleParserException(policyDocumentStream, exception);
		}
		catch (ParserConfigurationException exception)
		{
			return handleParserException(policyDocumentStream, exception);
		}
	}

	private Object handleParserException(InputStream policyDocumentStream, Exception exception) throws IOException
	{
		LOGGER.debug("Failed parsing data data for policy, assuming it is a String", exception);
		policyDocumentStream.reset();
		return policyDocumentStream;
	}

	private Document processSignatures(ObjectIdentifier policyIdentifier, Document signaturePolicyDocument, Collection<Algorithm> transforms) throws SignaturePolicyTransformException
	{
		for (Algorithm algorithm : transforms)
		{
			// Check if the algorith is one of the Canonicalizers
			if (canonicalizeTypes.contains(algorithm.getUri()))
			{
				LOGGER.debug("Found canonicalize type algorithm: [{}]", algorithm);
				signaturePolicyDocument = applyCanonicalizer(policyIdentifier, signaturePolicyDocument, algorithm.getUri());
				continue;
			}

			// Check if we need to filter
			if (algorithm instanceof XPath2FilterTransform)
			{
				LOGGER.debug("Found filter type algorithm: [{}]", algorithm);
				try
				{
					signaturePolicyDocument = applyTransformFilter(signaturePolicyDocument, (XPath2FilterTransform) algorithm);
				}
				catch (XPathExpressionException e)
				{
					throw new SignaturePolicyTransformException(policyIdentifier, e);
				}
				continue;
			}

			LOGGER.warn("Unsupported transform algorithm found! [{}]", algorithm);
		}

		return signaturePolicyDocument;
	}

	/**
	 * Applies the canonicalizer to the document. Invalid or unsupported variants will be skipped in this process.
	 *
	 * @param signaturePolicyDocument Document to apply canonicalizer
	 * @param type                    URI for the type of canonicalizer
	 * @return Canonicalized document
	 */
	private Document applyCanonicalizer(ObjectIdentifier policyIdentifier, Document signaturePolicyDocument, String type) throws SignaturePolicyTransformException
	{
		LOGGER.debug("Apply canonicalizer type [{}] to document", type);
		byte[] source = documentToByte(signaturePolicyDocument);
		byte[] canonicalizedData = null;

		Canonicalizer canonicalizer = null;
		try
		{
			canonicalizer = Canonicalizer.getInstance(type);
		}
		catch (InvalidCanonicalizerException e)
		{
			LOGGER.warn("Failed to initialize canonicalizer [{}] because: [{}]", type, e.getMessage(), e);
			throw new SignaturePolicyTransformException(policyIdentifier, e);
		}

		try
		{
			canonicalizedData = canonicalizer.canonicalize(source);
		}
		catch (CanonicalizationException e)
		{
			handleCanonicalizationException(policyIdentifier, type, e);
		}
		catch (ParserConfigurationException e)
		{
			handleCanonicalizationException(policyIdentifier, type, e);
		}
		catch (IOException e)
		{
			handleCanonicalizationException(policyIdentifier, type, e);
		}
		catch (SAXException e)
		{
			handleCanonicalizationException(policyIdentifier, type, e);
		}
		return byteToDocument(policyIdentifier, canonicalizedData);
	}

	private Document handleCanonicalizationException(ObjectIdentifier policyIdentifier, String type, Exception e) throws SignaturePolicyTransformException
	{
		LOGGER.warn("Failed to apply canonicalizer [{}] because: [{}]", type, e.getMessage(), e);
		throw new SignaturePolicyTransformException(policyIdentifier, e);
	}

	/**
	 * Applies the given transform (xml) node to the document. This will determine and and apply all specified xpath filters included the transform node.
	 * Invalid or unsupported variants or filters will be skipped in this process.
	 *
	 * @param signaturePolicyDocument
	 * @param transform
	 * @return transformed document
	 */
	private Document applyTransformFilter(Document signaturePolicyDocument, XPath2FilterTransform transform) throws XPathExpressionException
	{
		for (XPath2FilterTransform.XPath2Filter filter : transform.getFilters())
		{
			signaturePolicyDocument = applyTransformFilterXpath(signaturePolicyDocument, filter.getFilterType(), filter.getXPath());
		}
		return signaturePolicyDocument;
	}

	private Document applyTransformFilterXpath(Document signaturePolicyDocument, String type, String xpathExpression) throws XPathExpressionException
	{
		XPathFactory factory = XPathFactory.newInstance();

		XPath xpath = factory.newXPath();
		NodeList matchingNodeList = (NodeList) xpath.evaluate(xpathExpression, signaturePolicyDocument, XPathConstants.NODESET);
		LOGGER.debug("Found [{}] nodes for xpath [{}]", matchingNodeList.getLength(), xpathExpression);
		for (int index = 0; index < matchingNodeList.getLength(); index++)
		{
			Node matchingItem = matchingNodeList.item(index);

			if ("subtract".equalsIgnoreCase(type))
			{
				LOGGER.debug("Applying filter transform type [{}] for xpath [{}]", type, xpathExpression);
				Node parentNode = matchingItem.getParentNode();
				parentNode.removeChild(matchingItem);
			}
			else
			{
				LOGGER.warn("Unsupported xpath filter! type [{}] and xpath [{}]", type, xpathExpression);
			}
		}

		return signaturePolicyDocument;
	}

	private Document byteToDocument(ObjectIdentifier policyIdentifier, byte[] data) throws SignaturePolicyTransformException
	{
		try
		{
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			factory.setNamespaceAware(true);
			DocumentBuilder builder = factory.newDocumentBuilder();
			return builder.parse(new ByteArrayInputStream(data));
		}
		catch (ParserConfigurationException  e)
		{
			return handleConversionException(policyIdentifier, e);
		}
		catch (SAXException e)
		{
			return handleConversionException(policyIdentifier, e);
		}
		catch (IOException e)
		{
			return handleConversionException(policyIdentifier, e);
		}
	}

	private Document handleConversionException(ObjectIdentifier policyIdentifier, Exception e) throws SignaturePolicyTransformException
	{
		LOGGER.warn("Failed to convert byteToDocument because: [{}]", e.getMessage(), e);
		throw new SignaturePolicyTransformException(policyIdentifier, e);
	}

	private byte[] documentToByte(Document document)
	{
		if (document == null)
		{
			return null;
		}

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		org.apache.xml.security.utils.XMLUtils.outputDOM(document, baos);
		return baos.toByteArray();
	}
}
