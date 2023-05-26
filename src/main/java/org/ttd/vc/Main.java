package org.ttd.vc;

import com.google.gson.JsonObject;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ttd.vc.utils.Mnemonic;
import org.ttd.vc.utils.VCUtil;

import java.io.IOException;
import java.net.URI;
import java.security.*;
import java.time.LocalDateTime;

public class Main {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        CredentialSubject credentialSubject = new CredentialSubject();
        credentialSubject.addClaim("name", "Thusitha Dayaratne");
        credentialSubject.addClaim("job", "Research Fellow");
        credentialSubject.addClaim("university", "Monash University");
        credentialSubject.addClaim("id", "01128904");

        Credential credential = new Credential.Builder()
                .credentialSubject(credentialSubject)
                .credentialSubject(credentialSubject)
                .build();
        var dateTime = LocalDateTime.now();
        CredentialMetaData credentialMetaData = new CredentialMetaData.Builder()
                .id("1234567890")
                .issuer("MonashUniversity")
                .additionalType("MonashCredential")
                .issuanceDate(dateTime)
                .expirationDate(dateTime.plusYears(1))
                .build();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        byte[] keyBytesForSender = Mnemonic.toKey("sponsor ride say achieve senior height crumble promote " +
                "universe write dove bomb faculty side human taste paper grocery robot grab reason fork soul above " +
                "sphere");
        keyPairGenerator.initialize(256, new FixedSecureRandom(keyBytesForSender));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Proof proof = new Ed25519Signature2020(dateTime, credential, credentialMetaData, URI.create("key"),
                "assertion", keyPair.getPrivate());
        VerifiableCredential verifiableCredential = new VerifiableCredential.Builder()
                .credential(credential)
                .metadata(credentialMetaData)
                .proof(proof)
                .proof(proof)
                .build();
        JsonObject jsonRepresentation = VCUtil.getJsonRepresentation(verifiableCredential);
        System.out.println(jsonRepresentation);

    }
}
