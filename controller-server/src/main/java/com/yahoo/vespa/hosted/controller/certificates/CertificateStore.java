package com.yahoo.vespa.hosted.controller.certificates;

import com.yahoo.config.provision.ApplicationId;
import com.yahoo.vespa.hosted.controller.api.integration.certificates.ApplicationCertificate;

public abstract class CertificateStore {
    public abstract ApplicationCertificate getCertificate(ApplicationId applicationId);
    public abstract void storeCertificate(ApplicationId applicationId, ApplicationCertificate applicationCertificate);
}
