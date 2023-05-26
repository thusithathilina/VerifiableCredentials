package org.ttd.vc;

import java.net.URI;

public class Constants {
    public static final URI VC_DEFAULT_CONTEXT = URI.create("https://www.w3.org/2018/credentials/v1");

    public static final String CONTEXT = "@context";

    public static final String ID = "id";
    public static final String TYPE = "type";

    public static final String VERIFICATION_METHOD = "verificationMethod";
    public static final String PUBLIC_KEY_BASE_58 = "publicKeyBase58";
    public static final String ED25519 = "Ed25519";

    public static final String ISSUER = "issuer";
    public static final String ISSUANCE_DATE = "issuanceDate";
    public static final String CREDENTIAL_SUBJECT = "credentialSubject";
    public static final String PROOF = "proof";
}
