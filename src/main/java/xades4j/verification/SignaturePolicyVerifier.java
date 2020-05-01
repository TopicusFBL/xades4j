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
package xades4j.verification;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;

import org.apache.xml.security.signature.XMLSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import com.google.inject.Inject;

import xades4j.UnsupportedAlgorithmException;
import xades4j.policy_extension.SignaturePolicyTransformer;
import xades4j.properties.ObjectIdentifier;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignaturePolicyIdentifierProperty;
import xades4j.properties.SignaturePolicyImpliedProperty;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.SignaturePolicyDocumentProvider;
import xades4j.utils.MessageDigestUtils;

/**
 * @author Luís
 */
class SignaturePolicyVerifier implements QualifyingPropertyVerifier<SignaturePolicyData>
{

	private final SignaturePolicyDocumentProvider policyDocumentProvider;
	private final MessageDigestEngineProvider messageDigestProvider;

	private static final Logger LOGGER = LoggerFactory.getLogger(SignaturePolicyVerifier.class);

	@Inject
	public SignaturePolicyVerifier(
			SignaturePolicyDocumentProvider policyDocumentProvider,
			MessageDigestEngineProvider messageDigestProvider)
	{
		this.policyDocumentProvider = policyDocumentProvider;
		this.messageDigestProvider = messageDigestProvider;
	}

	@Override
	public QualifyingProperty verify(
			SignaturePolicyData propData,
			QualifyingPropertyVerificationContext ctx) throws SignaturePolicyVerificationException
	{
		ObjectIdentifier policyId = propData.getIdentifier();

		QualifyingPropertyVerificationContext.SignedObjectsData signedObjectsData = ctx.getSignedObjectsData();

		Document xmlSignatureDocument = ctx.getSignature().getDocument();

		if (null == policyId)
		{
			return new SignaturePolicyImpliedProperty();
		}

		SignaturePolicyTransformer signaturePolicyTransformer = new SignaturePolicyTransformer();
		InputStream sigDocStream = signaturePolicyTransformer.processPolicyForIdentifier(this.policyDocumentProvider, policyId, propData.getTransforms());
		if (null == sigDocStream)
		{
			throw new SignaturePolicyNotAvailableException(policyId, null);
		}

		try
		{
			MessageDigest md = this.messageDigestProvider.getEngine(propData.getDigestAlgorithm());
			byte[] sigDocDigest = MessageDigestUtils.digestStream(md, sigDocStream);

			LOGGER.debug("Check calculated digest [{}] matches [{}] for policyid[{}] and algorithm [{}]", new Object[] {new String(org.apache.commons.codec.binary.Base64.encodeBase64(sigDocDigest)), new String(org.apache.commons.codec.binary.Base64.encodeBase64(propData.getDigestValue())), policyId.getIdentifier(), propData.getDigestAlgorithm()});
			// Check the document digest.
			if (!Arrays.equals(sigDocDigest, propData.getDigestValue()))
			{
				LOGGER.warn("Document digest doesn't match!");
				throw new SignaturePolicyDigestMismatchException(policyId);
			}
			return new SignaturePolicyIdentifierProperty(policyId, sigDocStream)
					.withLocationUrl(propData.getLocationUrl());
		}
		catch (IOException ex)
		{
			throw new SignaturePolicyNotAvailableException(policyId, ex);
		}
		catch (UnsupportedAlgorithmException ex)
		{
			throw new SignaturePolicyCannotDigestException(policyId, ex);
		}
		finally
		{
			try
			{
				sigDocStream.close();
			}
			catch (IOException ex)
			{
				throw new SignaturePolicyNotAvailableException(policyId, ex);
			}
		}
	}
}
