package com.github.wegoo.cain.cert.path;

import com.github.wegoo.cain.cert.X509CertificateHolder;
import com.github.wegoo.cain.util.Memoable;

public interface CertPathValidation
    extends Memoable
{
    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException;
}
