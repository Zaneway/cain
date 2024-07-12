package com.github.wegoo.cain.its;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import com.github.wegoo.cain.asn1.ASN1Encodable;
import com.github.wegoo.cain.oer.Element;
import com.github.wegoo.cain.oer.OEREncoder;
import com.github.wegoo.cain.oer.OERInputStream;
import com.github.wegoo.cain.oer.its.etsi103097.EtsiTs103097DataEncrypted;
import com.github.wegoo.cain.oer.its.ieee1609dot2.EncryptedData;
import com.github.wegoo.cain.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import com.github.wegoo.cain.oer.its.ieee1609dot2.RecipientInfo;
import com.github.wegoo.cain.oer.its.template.etsi103097.EtsiTs103097Module;
import com.github.wegoo.cain.util.CollectionStore;
import com.github.wegoo.cain.util.Store;

public class ETSIEncryptedData
{
    private static final Element oerDef = EtsiTs103097Module.EtsiTs103097Data_Encrypted.build();

    private final EncryptedData encryptedData;

    public ETSIEncryptedData(byte[] oerEncoded)
        throws IOException
    {
        this(new ByteArrayInputStream(oerEncoded));
    }

    public ETSIEncryptedData(InputStream str)
        throws IOException
    {
        OERInputStream oerIn;
        if (str instanceof OERInputStream)
        {
            oerIn = (OERInputStream)str;
        }
        else
        {
            oerIn = new OERInputStream(str);
        }
        ASN1Encodable asn1 = oerIn.parse(oerDef);

        Ieee1609Dot2Content content = EtsiTs103097DataEncrypted.getInstance(asn1).getContent();
        if (content.getChoice() != Ieee1609Dot2Content.encryptedData)
        {
            throw new IllegalStateException("EtsiTs103097Data-Encrypted did not have encrypted data content");
        }
        this.encryptedData = EncryptedData.getInstance(content.getIeee1609Dot2Content());
    }

    ETSIEncryptedData(EncryptedData data)
    {
        this.encryptedData = data;
    }

    public byte[] getEncoded()
    {
        return OEREncoder.toByteArray(new EtsiTs103097DataEncrypted(
            Ieee1609Dot2Content
                .encryptedData(encryptedData)
        ), oerDef);
    }

    public EncryptedData getEncryptedData()
    {
        return encryptedData;
    }

    public Store<ETSIRecipientInfo> getRecipients()
    {
        List<ETSIRecipientInfo> recipients = new ArrayList<ETSIRecipientInfo>();
        for (RecipientInfo ri : encryptedData.getRecipients().getRecipientInfos())
        {
            recipients.add(new ETSIRecipientInfo(encryptedData, ri));
        }
        return new CollectionStore<ETSIRecipientInfo>(recipients);
    }

}
