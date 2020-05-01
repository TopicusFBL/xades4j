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
package xades4j.properties;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Collection;

import xades4j.algorithms.Algorithm;
import xades4j.utils.CollectionUtils;

/**
 * An explicit and unambiguous identifier of a signature policy.
 * @see SignaturePolicyBase
 * @author Luís
 */
public final class SignaturePolicyIdentifierProperty extends SignaturePolicyBase
{
    private final ObjectIdentifier identifier;
    private byte[] policyDocumentData;
    private InputStream policyDocumentStream;
    private String locationUrl;
    private Collection<Algorithm> transforms;

    /**
     * @param identifier the policy identifier
     * @param policyDocumentStream an {@code InputStream} to the policy document
     * @throws NullPointerException if {@code policyDocumentStream} is {@code null}
     */
    public SignaturePolicyIdentifierProperty(
            ObjectIdentifier identifier,
            InputStream policyDocumentStream)
    {
        if (null == policyDocumentStream)
            throw new NullPointerException();

        this.identifier = identifier;
        this.policyDocumentStream = policyDocumentStream;
    }

    /**
     * @param identifier the policy identifier
     * @param policyDocumentData the content of the policy document
     * @throws NullPointerException if {@code policyDocumentData} is {@code null}
     */
    public SignaturePolicyIdentifierProperty(
            ObjectIdentifier identifier,
            byte[] policyDocumentData)
    {
        if (null == policyDocumentData)
            throw new NullPointerException();

        this.identifier = identifier;
        this.policyDocumentData = policyDocumentData;
    }

    /**
     * Gets the content of the policy document
     * @return the content or {@code null} if the instance was created with a stream
     */
    public byte[] getPolicyDocumentData()
    {
        return policyDocumentData;
    }

    /**
     * Gets the stream to the policy document. If the instance was created with
     * the policy document content, a ByteArrayInputStream is returned.
     * @return the stream
     */
    public InputStream getPolicyDocumentStream()
    {
        if (null == policyDocumentStream)
            policyDocumentStream = new ByteArrayInputStream(policyDocumentData);
        return policyDocumentStream;
    }

    public ObjectIdentifier getIdentifier()
    {
        return identifier;
    }
    
    /**
     * Adds a URL where a copy of the signature policy may be obtained. This will
     * be added as a qualifier.
     * @param url the location URL
     * @return the current instance
     */
    public SignaturePolicyIdentifierProperty withLocationUrl(String url)
    {
        locationUrl = url;
        return this;
    }
    
    public String getLocationUrl()
    {
        return locationUrl;
    }

    /**
     * Registers a transform to be applied to the policy file at the signature
     * generation. Each transform will result in a {@code ds:Transform} element
     * within the {@code ds:SignaturePolicyIdentifier} resulting from the current
     * policy identifier.
     *
     * @param transform the transform to be applied
     * @return the current instance
     *
     * @throws NullPointerException if {@code transform} is {@code null}
     * @throws IllegalStateException if the transform (instance) is already
     *                                  present
     */
    public final SignaturePolicyIdentifierProperty withTransform(Algorithm transform)
    {
        if (null == transform)
        {
            throw new NullPointerException("Transform cannot be null");
        }

        transforms = CollectionUtils.newIfNull(transforms, 2);
        if (!transforms.add(transform))
        {
            throw new IllegalStateException("Transform was already added");
        }

        return this;
    }

    public Collection<Algorithm> getTransforms()
    {
        return CollectionUtils.emptyIfNull(transforms);
    }
}
