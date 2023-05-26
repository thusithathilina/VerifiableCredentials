# VerifiableCredentials
This provides a basic implementation of the W3C Verifiable Credential specification which was approved as a recommendation in late June 2022
Specification can be found on https://www.w3.org/TR/vc-data-model/

Please refer to Main.java class for sample usage

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

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
    byte[] keyBytesForSender = Mnemonic.toKey("sponsor ride say achieve senior height crumble promote " +
            "universe write dove bomb faculty side human taste paper grocery robot grab reason fork soul above " +
            "sphere");
    keyPairGenerator.initialize(256, new FixedSecureRandom(keyBytesForSender));
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    Proof proof = new Ed25519Signature2020(dateTime, credential, credentialMetaData, URI.create("linkToPublicKey"),
            "assertion", keyPair.getPrivate());

    VerifiableCredential verifiableCredential = new VerifiableCredential.Builder()
            .credential(credential)
            .metadata(credentialMetaData)
            .proof(proof)
            .build();
    JsonObject jsonRepresentation = VCUtil.getJsonRepresentation(verifiableCredential);
    System.out.println(jsonRepresentation);