package org.ttd.vc;

import com.auth0.jwt.algorithms.Algorithm;
import com.google.gson.JsonObject;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ttd.vc.utils.Mnemonic;
import org.ttd.vc.utils.VCUtil;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
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
        credentialSubject.addClaim("id", "0123456789");

        Credential credential = new Credential.Builder()
                .credentialSubject(credentialSubject)
                .build();
        var dateTime = LocalDateTime.now();
        CredentialMetaData credentialMetaData = new CredentialMetaData.Builder()
                .id("vc12345")
                .issuer("MonashUniversity")
                .additionalType("MonashCredential")
                .issuanceDate(dateTime)
                .expirationDate(dateTime.plusYears(1))
                .build();

        // Build a VC without embedded proof
        VerifiableCredential vc = new VerifiableCredential.Builder()
                .credential(credential)
                .metadata(credentialMetaData)
                .build();

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        KeyPair keyPair2 = keyGenerator.generateKeyPair();
        Algorithm algorithm = Algorithm.ECDSA256(null, (ECPrivateKey) keyPair2.getPrivate());

        // Generate an external proof for the VC (JWT)
        String vcJwt = VCUtil.vcToJwT(vc, algorithm);
        System.out.println(vcJwt);

        // Verify the JWT
        Verifier.verify(vcJwt, Algorithm.ECDSA256((ECPublicKey) keyPair2.getPublic(), null));
        System.out.println("JWT verification success");

        // Generate an VC with embedded proof
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        byte[] keyBytesForSender = Mnemonic.toKey("sponsor ride say achieve senior height crumble promote " +
                "universe write dove bomb faculty side human taste paper grocery robot grab reason fork soul above " +
                "sphere");
        keyPairGenerator.initialize(256, new FixedSecureRandom(keyBytesForSender));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Proof proof = new Ed25519Signature2020(dateTime, credential, credentialMetaData, URI.create("linkToPublicKey"),
                "assertion", keyPair.getPrivate());

        VerifiableCredential vcWithEmbeddedProof = new VerifiableCredential.Builder()
                .credential(credential)
                .metadata(credentialMetaData)
                .proof(proof)
                .build();

        JsonObject jsonRepresentation = VCUtil.getJsonRepresentation(vcWithEmbeddedProof);
        System.out.println(jsonRepresentation);
    }
}
