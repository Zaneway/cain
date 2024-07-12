package com.github.wegoo.cain.its;

import java.util.ArrayList;
import java.util.List;

import com.github.wegoo.cain.its.operator.ETSIDataEncryptor;
import com.github.wegoo.cain.oer.its.ieee1609dot2.AesCcmCiphertext;
import com.github.wegoo.cain.oer.its.ieee1609dot2.EncryptedData;
import com.github.wegoo.cain.oer.its.ieee1609dot2.SequenceOfRecipientInfo;
import com.github.wegoo.cain.oer.its.ieee1609dot2.SymmetricCiphertext;

public class ETSIEncryptedDataBuilder
{
    private final List<ETSIRecipientInfoBuilder> recipientInfoBuilders = new ArrayList<ETSIRecipientInfoBuilder>();

    public ETSIEncryptedDataBuilder()
    {
    }

    public void addRecipientInfoBuilder(ETSIRecipientInfoBuilder recipientInfoBuilder)
    {
        recipientInfoBuilders.add(recipientInfoBuilder);
    }

    public ETSIEncryptedData build(ETSIDataEncryptor encryptor, byte[] content)
    {
        byte[] opaque = encryptor.encrypt(content);
        byte[] key = encryptor.getKey();
        byte[] nonce = encryptor.getNonce();

        SequenceOfRecipientInfo.Builder builder = SequenceOfRecipientInfo.builder();
        for (ETSIRecipientInfoBuilder recipientInfoBuilder : recipientInfoBuilders)
        {
            builder.addRecipients(recipientInfoBuilder.build(key));
        }

        // Encryption goes here

        return new ETSIEncryptedData(EncryptedData.builder()
            .setRecipients(builder.createSequenceOfRecipientInfo())
            .setCiphertext(SymmetricCiphertext.aes128ccm(AesCcmCiphertext.builder()
                .setCcmCiphertext(opaque)
                .setNonce(nonce)
                .createAesCcmCiphertext())).createEncryptedData()
        );
    }
}
