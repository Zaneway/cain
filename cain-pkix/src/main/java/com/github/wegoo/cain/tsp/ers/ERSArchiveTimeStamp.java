package com.github.wegoo.cain.tsp.ers;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;

import com.github.wegoo.cain.asn1.tsp.ArchiveTimeStamp;
import com.github.wegoo.cain.asn1.tsp.PartialHashtree;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;
import com.github.wegoo.cain.cert.X509CertificateHolder;
import com.github.wegoo.cain.cms.SignerInformationVerifier;
import com.github.wegoo.cain.operator.DigestCalculator;
import com.github.wegoo.cain.operator.DigestCalculatorProvider;
import com.github.wegoo.cain.operator.OperatorCreationException;
import com.github.wegoo.cain.tsp.TSPException;
import com.github.wegoo.cain.tsp.TimeStampToken;
import com.github.wegoo.cain.util.Arrays;
import com.github.wegoo.cain.util.Store;

/**
 * RFC 4998 ArchiveTimeStamp.
 */
public class ERSArchiveTimeStamp
{
    private final ArchiveTimeStamp archiveTimeStamp;
    private final DigestCalculator digCalc;
    private final TimeStampToken timeStampToken;
    private final byte[] previousChainsDigest;

    private ERSRootNodeCalculator rootNodeCalculator = new BinaryTreeRootCalculator();

    public ERSArchiveTimeStamp(byte[] archiveTimeStamp, DigestCalculatorProvider digCalcProv)
        throws TSPException, ERSException
    {
        this(ArchiveTimeStamp.getInstance(archiveTimeStamp), digCalcProv);
    }

    public ERSArchiveTimeStamp(ArchiveTimeStamp archiveTimeStamp, DigestCalculatorProvider digCalcProv)
        throws TSPException, ERSException
    {
        this.previousChainsDigest = null;
        try
        {
            this.archiveTimeStamp = archiveTimeStamp;
            this.timeStampToken = new TimeStampToken(archiveTimeStamp.getTimeStamp());
            this.digCalc = digCalcProv.get(archiveTimeStamp.getDigestAlgorithmIdentifier());
        }
        catch (IOException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
        catch (OperatorCreationException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
    }

    ERSArchiveTimeStamp(ArchiveTimeStamp archiveTimeStamp, DigestCalculator digCalc)
        throws TSPException, ERSException
    {
        this.previousChainsDigest = null;
        try
        {
            this.archiveTimeStamp = archiveTimeStamp;
            this.timeStampToken = new TimeStampToken(archiveTimeStamp.getTimeStamp());
            this.digCalc = digCalc;
        }
        catch (IOException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
    }

    ERSArchiveTimeStamp(byte[] previousChainsDigest, ArchiveTimeStamp archiveTimeStamp, DigestCalculatorProvider digCalcProv)
        throws TSPException, ERSException
    {
        this.previousChainsDigest = previousChainsDigest;
        try
        {
            this.archiveTimeStamp = archiveTimeStamp;
            this.timeStampToken = new TimeStampToken(archiveTimeStamp.getTimeStamp());
            this.digCalc = digCalcProv.get(archiveTimeStamp.getDigestAlgorithmIdentifier());
        }
        catch (IOException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
        catch (OperatorCreationException e)
        {
            throw new ERSException(e.getMessage(), e);
        }
    }

    public AlgorithmIdentifier getDigestAlgorithmIdentifier()
    {
        return archiveTimeStamp.getDigestAlgorithmIdentifier();
    }

    public void validatePresent(ERSData data, Date atDate)
        throws ERSException
    {
        validatePresent(data instanceof ERSDataGroup, data.getHash(digCalc, previousChainsDigest), atDate);
    }

    public boolean isContaining(ERSData data, Date atDate)
        throws ERSException
    {
        if (timeStampToken.getTimeStampInfo().getGenTime().after(atDate))
        {
            throw new ArchiveTimeStampValidationException("timestamp generation time is in the future");
        }

        try
        {
            validatePresent(data, atDate);

            return true;
        }
        catch (Exception e)
        {
            return false;
        }
    }

    public void validatePresent(boolean isDataGroup, byte[] hash, Date atDate)
        throws ERSException
    {
        if (timeStampToken.getTimeStampInfo().getGenTime().after(atDate))
        {
            throw new ArchiveTimeStampValidationException("timestamp generation time is in the future");
        }

        checkContainsHashValue(isDataGroup, hash, digCalc);

        PartialHashtree[] partialTree = archiveTimeStamp.getReducedHashTree();
        byte[] rootHash;

        if (partialTree != null)
        {
            rootHash = rootNodeCalculator.recoverRootHash(digCalc, archiveTimeStamp.getReducedHashTree());
        }
        else
        {
            rootHash = hash;
        }

        checkTimeStampValid(timeStampToken, rootHash);
    }

    public TimeStampToken getTimeStampToken()
    {
        return timeStampToken;
    }

    /**
     * Return the TimeStamp signing certificate if it is present.
     *
     * @return the TimeStamp signing certificate.
     */
    public X509CertificateHolder getSigningCertificate()
    {
        final Store<X509CertificateHolder> certificateStore = timeStampToken.getCertificates();
        if (certificateStore != null)
        {
            final Collection<X509CertificateHolder> certs = certificateStore.getMatches(timeStampToken.getSID());
            if (!certs.isEmpty())
            {
                return (X509CertificateHolder)certs.iterator().next();
            }
        }

        return null;
    }

    /**
     * Validate the time stamp associated with this ArchiveTimeStamp.
     *
     * @param verifier signer verifier for the contained time stamp.
     * @throws TSPException in case of validation failure or error.
     */
    public void validate(SignerInformationVerifier verifier)
        throws TSPException
    {
        timeStampToken.validate(verifier);
    }

    void checkContainsHashValue(boolean isGroup, final byte[] hash, final DigestCalculator digCalc)
        throws ArchiveTimeStampValidationException
    {
        PartialHashtree[] reducedHashTree = archiveTimeStamp.getReducedHashTree();

        if (reducedHashTree != null)
        {
            // RFC 4998, Section 4.3, part 2, search first node only.
            PartialHashtree current = reducedHashTree[0];

            if (!isGroup && current.containsHash(hash))
            {
                return;
            }
            // check we're not a composite document hash
            if (current.getValueCount() > 1)
            {
                if (Arrays.areEqual(hash, ERSUtil.calculateBranchHash(digCalc, current.getValues())))
                {
                    return;
                }
            }
            throw new ArchiveTimeStampValidationException("object hash not found");
        }
        else
        {
            if (!Arrays.areEqual(hash, timeStampToken.getTimeStampInfo().getMessageImprintDigest()))
            {
                throw new ArchiveTimeStampValidationException("object hash not found in wrapped timestamp");
            }
        }
    }

    void checkTimeStampValid(final TimeStampToken timeStampToken, final byte[] hash)
        throws ArchiveTimeStampValidationException
    {
        if (hash != null)
        {
            if (!Arrays.areEqual(hash, timeStampToken.getTimeStampInfo().getMessageImprintDigest()))
            {
                throw new ArchiveTimeStampValidationException("timestamp hash does not match root");
            }
        }
    }

    /**
     * Return the generation time of the time-stamp associated with
     * this archive time stamp.
     *
     * @return the time the associated time-stamp was created.
     */
    public Date getGenTime()
    {
        return timeStampToken.getTimeStampInfo().getGenTime();
    }

    /**
     * Return the not-after date for the time-stamp's signing certificate
     * if it is present.
     *
     * @return the issuing TSP server not-after date, or null if not present.
     */
    public Date getExpiryTime()
    {
        X509CertificateHolder crtHolder = getSigningCertificate();
        if (crtHolder != null)
        {
            return crtHolder.getNotAfter();
        }
        return null;
    }

    public ArchiveTimeStamp toASN1Structure()
    {
        return archiveTimeStamp;
    }

    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return archiveTimeStamp.getEncoded();
    }

    /**
     * Build an ArchiveTimeStamp from a regular time stamp token.
     *
     * @param tspToken the TimeStampToken in the regular time stamp.
     * @param digCalcProv a digest calculator provider for use with the time stamp.
     * @return an ERSArchiveTimeStamp containing the time stamp.
     * @throws TSPException on a failure to parse the time stamp token data.
     * @throws ERSException on a failure to convert the time stamp token to an archive time stamp.
     */
    public static ERSArchiveTimeStamp fromTimeStampToken(TimeStampToken tspToken, DigestCalculatorProvider digCalcProv)
        throws TSPException, ERSException
    {
        return new ERSArchiveTimeStamp(new ArchiveTimeStamp(tspToken.toCMSSignedData().toASN1Structure()), digCalcProv);
    }
}
