package org.ttd.vc.utils;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.ttd.vc.*;

import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;

public class VCUtil {

    private static final GsonBuilder gsonBuilder = new GsonBuilder();
    public static Gson gson;

    static {
        gsonBuilder.registerTypeAdapter(LocalDateTime.class, new LocalDateTimeSerializer());
        gson = gsonBuilder.create();
    }

    public static JsonObject getJsonRepresentation(VerifiableCredential verifiableCredential) {
        JsonObject vc = new JsonObject();

        CredentialMetaData credentialMetaData = verifiableCredential.getCredentialMetaData();
        List<URI> contexts = credentialMetaData.getContexts();
        if (contexts.size() == 1)
            vc.add(Constants.CONTEXT, gson.toJsonTree(contexts.get(0)));
        else if (contexts.size() > 1) {
            vc.add(Constants.CONTEXT, gson.toJsonTree(contexts));
        }

        vc.add(Constants.ID, gson.toJsonTree(credentialMetaData.getId()));
        vc.add(Constants.TYPE, gson.toJsonTree(credentialMetaData.getTypes()));
        vc.add(Constants.ISSUER, gson.toJsonTree(credentialMetaData.getIssuer()));
        vc.add(Constants.ISSUANCE_DATE, gson.toJsonTree(credentialMetaData.getIssuanceDate()));

        List<CredentialSubject> credentialSubjects = verifiableCredential.getCredential().getCredentialSubjects();
        if (credentialSubjects.size() == 1)
            vc.add(Constants.CREDENTIAL_SUBJECT, credentialSubjects.get(0).toJson());
        else {
            JsonArray jsonArray = new JsonArray();
            credentialSubjects.forEach(sub -> jsonArray.add(sub.toJson()));
            vc.add(Constants.CREDENTIAL_SUBJECT, jsonArray);
        }

        List<Proof> proofs = verifiableCredential.getProofs();
        vc.add(Constants.PROOF, gson.toJsonTree((proofs)));

        return vc;
    }


    public static String vcToJwT(VerifiableCredential verifiableCredential, Algorithm hashAlgorithm) {
        JsonObject jsonRepresentation = getJsonRepresentation(verifiableCredential);
        jsonRepresentation.remove(Constants.PROOF);
        JsonObject jsonObject = new JsonObject();
        jsonObject.add("VC", jsonRepresentation);

        JWTCreator.Builder builder = JWT.create();
        builder.withPayload(jsonObject.toString());

        CredentialMetaData credentialMetaData = verifiableCredential.getCredentialMetaData();
        builder.withIssuer(credentialMetaData.getIssuer().toString());
        builder.withIssuedAt(credentialMetaData.getIssuanceDate().toInstant(ZoneOffset.UTC));
        builder.withExpiresAt(credentialMetaData.getExpirationDate().toInstant(ZoneOffset.UTC));
        return builder.sign(hashAlgorithm);
    }
}
