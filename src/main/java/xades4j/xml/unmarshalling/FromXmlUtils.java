/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 *
 * XAdES4j is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or any later version.
 *
 * XAdES4j is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with XAdES4j. If not, see <http://www.gnu.org/licenses/>.
 */
package xades4j.xml.unmarshalling;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import org.w3c.dom.Element;

import xades4j.algorithms.Algorithm;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.algorithms.XPath2FilterTransform;
import xades4j.properties.IdentifierType;
import xades4j.properties.ObjectIdentifier;
import xades4j.properties.data.BaseCertRefsData;
import xades4j.properties.data.CertRef;
import xades4j.xml.bind.xades.XmlCertIDListType;
import xades4j.xml.bind.xades.XmlCertIDType;
import xades4j.xml.bind.xades.XmlDigestAlgAndValueType;
import xades4j.xml.bind.xades.XmlIdentifierType;
import xades4j.xml.bind.xades.XmlObjectIdentifierType;
import xades4j.xml.bind.xades.XmlQualifierType;
import xades4j.xml.bind.xmldsig.XmlTransformType;
import xades4j.xml.bind.xmldsig.XmlTransformsType;
import xades4j.xml.bind.xmldsig.XmlX509IssuerSerialType;

/**
 * @author Luís
 */
class FromXmlUtils
{
	private FromXmlUtils()
	{
	}

	static void createAndCertificateRefs(
			XmlCertIDListType xmlCertRefs,
			BaseCertRefsData certRefsData)
	{
		for (XmlCertIDType xmlCertIDType : xmlCertRefs.getCert())
		{
			/* All the elements within Cert are marked with 'required' */

			XmlX509IssuerSerialType is = xmlCertIDType.getIssuerSerial();
			XmlDigestAlgAndValueType d = xmlCertIDType.getCertDigest();

			CertRef ref = new CertRef(
					is.getX509IssuerName(),
					is.getX509SerialNumber(),
					d.getDigestMethod().getAlgorithm(),
					d.getDigestValue()); // Digest value is already decoded.

			certRefsData.addCertRef(ref);
		}
	}

	private static final Map<XmlQualifierType, IdentifierType> identifierTypeConv;

	static
	{
		identifierTypeConv = new HashMap<XmlQualifierType, IdentifierType>(3);
		identifierTypeConv.put(null, IdentifierType.URI);
		identifierTypeConv.put(XmlQualifierType.OID_AS_URI, IdentifierType.OIDAsURI);
		identifierTypeConv.put(XmlQualifierType.OID_AS_URN, IdentifierType.OIDAsURN);
	}

	static ObjectIdentifier getObjectIdentifier(XmlObjectIdentifierType xmlObjId)
	{
		if (null == xmlObjId)
		{
			return null;
		}
		XmlIdentifierType xmlId = xmlObjId.getIdentifier();
		return new ObjectIdentifier(
				xmlId.getValue(),
				identifierTypeConv.get(xmlId.getQualifier()),
				xmlObjId.getDescription());
	}

	static Collection<Algorithm> getTransforms(XmlTransformsType xmlTransforms)
	{
		if (null == xmlTransforms)
		{
			return Collections.EMPTY_LIST;
		}
		Collection<Algorithm> result = new ArrayList<Algorithm>();
		for (XmlTransformType xmlTransform : xmlTransforms.getTransform())
		{
			if (XPath2FilterContainer.XPathFilter2NS.equalsIgnoreCase(xmlTransform.getAlgorithm()))
			{
				addXPath2Filters(result, xmlTransform);
			}
			else
			{
				Algorithm algorithm = new GenericAlgorithm(xmlTransform.getAlgorithm());
				result.add(algorithm);
			}
		}
		return result;
	}

	private static void addXPath2Filters(Collection<Algorithm> result, XmlTransformType xmlTransform)
	{
		List<Object> content = xmlTransform.getContent();
		for (Object object : content)
		{
			if (!(object instanceof Element))
			{
				continue;
			}
			XPath2FilterTransform filter = parseXPath2Filter((Element) object);
			if(filter != null)
			{
				result.add(filter);
			}
		}
	}

	private static XPath2FilterTransform parseXPath2Filter(Element element)
	{
		if (!"dsig-xpath:XPath".equalsIgnoreCase(element.getTagName()))
		{
			return null;
		}
		if (!XPath2FilterContainer.XPathFilter2NS.equalsIgnoreCase(element.getAttribute("xmlns:dsig-xpath")))
		{
			return null;
		}
		String xpath = element.getTextContent();
		String filter = element.getAttribute("Filter");
		if (XPath2FilterContainer.SUBTRACT.equalsIgnoreCase(filter))
		{
			return XPath2FilterTransform.XPath2Filter.subtract(xpath);
		}
		else if (XPath2FilterContainer.INTERSECT.equalsIgnoreCase(filter))
		{
			return XPath2FilterTransform.XPath2Filter.intersect(xpath);
		}
		else if (XPath2FilterContainer.UNION.equalsIgnoreCase(filter))
		{
			return XPath2FilterTransform.XPath2Filter.union(xpath);
		}
		return null;
	}
}
