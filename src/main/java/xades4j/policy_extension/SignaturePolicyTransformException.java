package xades4j.policy_extension;

import xades4j.properties.ObjectIdentifier;
import xades4j.verification.SignaturePolicyVerificationException;

public class SignaturePolicyTransformException extends SignaturePolicyVerificationException
{

	public SignaturePolicyTransformException(ObjectIdentifier signaturePolicyId, Throwable cause)
	{
		super(signaturePolicyId, cause);
	}

	@Override
	protected String getVerificationMessage()
	{
		return "failed transforming policy";
	}
}
