package org.ttd.vc;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.reflect.TypeToken;

import java.util.ArrayList;
import java.util.List;

public class Credential {

    private final List<CredentialSubject> credentialSubjects;

    private Credential(List<CredentialSubject> credentialSubjects) {
        this.credentialSubjects = credentialSubjects;
    }

    public List<CredentialSubject> getCredentialSubjects() {
        return credentialSubjects;
    }

    public JsonArray toJson() {
        JsonArray jsonArray = new JsonArray();
        jsonArray.add(new Gson().toJsonTree(credentialSubjects, new TypeToken<List<CredentialSubject>>() {}.getType()));
        return jsonArray;
    }

    public static class Builder {
        private final List<CredentialSubject> credentialSubjects = new ArrayList<>();

        public Builder credentialSubject(CredentialSubject credentialSubject) {
            credentialSubjects.add(credentialSubject);
            return this;
        }

        public Builder credentialSubjects(List<CredentialSubject> credentialSubjects) {
            this.credentialSubjects.addAll(credentialSubjects);
            return this;
        }

        public Credential build() {
            if (credentialSubjects.size() == 0)
                throw new RuntimeException("Empty credential");
            return new Credential(credentialSubjects);
        }
    }
}
