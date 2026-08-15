CREATE TABLE registration_legal_acceptance (
    user_id VARCHAR(36) PRIMARY KEY,
    legal_version VARCHAR(64) NOT NULL,
    terms_accepted BOOLEAN NOT NULL,
    privacy_notice_acknowledged BOOLEAN NOT NULL,
    age_eligibility_confirmed BOOLEAN NOT NULL,
    accepted_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT fk_registration_legal_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ck_registration_legal_terms CHECK (terms_accepted),
    CONSTRAINT ck_registration_legal_privacy CHECK (privacy_notice_acknowledged),
    CONSTRAINT ck_registration_legal_age CHECK (age_eligibility_confirmed)
);
