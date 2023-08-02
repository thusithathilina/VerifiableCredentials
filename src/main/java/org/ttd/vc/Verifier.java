package org.ttd.vc;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.JWTVerifier;

/**
 * This class is used to verify the JWT based VCs
 */
public class Verifier {

    private Verifier() {
    }

    /**
     *
     * @param vcJwt JWT token (VC) needs to be verified
     * @param hashAlgorithm Algorithm used to generate the JWT token
     * @return true if the verification success otherwise throws JWTVerificationException
     */
    public static boolean verify(String vcJwt, Algorithm hashAlgorithm) {
        JWTVerifier verifier = JWT.require(hashAlgorithm)
                .ignoreIssuedAt()
                .build();
        verifier.verify(vcJwt);
        return true;
    }
}
