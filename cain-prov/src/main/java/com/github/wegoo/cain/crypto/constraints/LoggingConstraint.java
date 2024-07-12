package com.github.wegoo.cain.crypto.constraints;

import java.util.Set;
import java.util.logging.Level;

import com.github.wegoo.cain.crypto.CryptoServiceProperties;

public class LoggingConstraint
    extends ServicesConstraint
{
    protected LoggingConstraint(Set<String> exceptions)
    {
        super(exceptions);
    }

    public void check(CryptoServiceProperties service)
    {
        if (isException(service.getServiceName()))
        {
            return;
        }

        if (LOG.isLoggable(Level.INFO))
        {
            LOG.info("service " + service.getServiceName() + " referenced [" + service.getServiceName() + ", " + service.bitsOfSecurity() + ", " + service.getPurpose());
        }
    }
}
