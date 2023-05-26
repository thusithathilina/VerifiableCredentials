package org.ttd.vc;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.ipfs.multibase.Multibase;
import org.apache.commons.codec.digest.DigestUtils;
import org.ttd.vc.utils.JsonCanonicalizer;
import org.ttd.vc.utils.LocalDateTimeSerializer;
import org.ttd.vc.utils.VCUtil;


import java.io.IOException;
import java.net.URI;
import java.security.*;
import java.time.LocalDateTime;

public class Ed25519Signature2020 implements Proof {

    private final String TYPE = "Ed25519Signature2020";
    private LocalDateTime created;
    private URI verificationMethod;
    private String proofPurpose;
    private String proofValue;

    public Ed25519Signature2020(LocalDateTime created, Credential credential, CredentialMetaData credentialMetaData,
                                URI verificationMethod, String purpose, PrivateKey privateKey)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException {
        this.created = created;
        this.verificationMethod = verificationMethod;
        this.proofPurpose = purpose;
        this.proofValue = sign(credential, credentialMetaData, privateKey);

    }

    public String getType() {
        return TYPE;
    }

    public LocalDateTime getCreated() {
        return created;
    }

    public URI getVerificationMethod() {
        return verificationMethod;
    }

    @Override
    public String toString() {
        return VCUtil.gson.toJson(this);
    }

    public String getProofPurpose() {
        return proofPurpose;
    }

    public String getProof() {
        return proofValue;
    }

    private String sign(Credential credential, CredentialMetaData credentialMetaData, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
//        JSONObject jsonRepresentation = VCUtil.getJsonRepresentation(credential);
//        jsonRepresentation.remove(Constants.PROOF);


        String s = VCUtil.gson.toJson(credentialMetaData);
        String encodedString = new JsonCanonicalizer(credential.toJson().toString()).getEncodedString();

        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(privateKey);
        signature.update(DigestUtils.sha256(encodedString));
        return Multibase.encode(Multibase.Base.Base58BTC, signature.sign());
    }
}
