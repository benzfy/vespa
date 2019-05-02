package com.yahoo.vespa.hosted.controller.certificates;

import com.yahoo.config.provision.ApplicationId;
import com.yahoo.vespa.hosted.controller.api.integration.certificates.ApplicationCertificate;
import com.yahoo.vespa.hosted.controller.api.integration.certificates.CertificateProvider;
import com.yahoo.vespa.hosted.controller.api.integration.certificates.KeyPairProvider;
import com.yahoo.vespa.hosted.controller.api.integration.certificates.VersionedKeyPair;
import com.yahoo.vespa.hosted.controller.integration.ZoneRegistryMock;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

public class CertificateManagerTest {

    class MockCertificateStore extends CertificateStore {

        @Override
        public ApplicationCertificate getCertificate(ApplicationId applicationId) {
            return null;
        }

        @Override
        public void storeCertificate(ApplicationId applicationId, ApplicationCertificate applicationCertificate) {

        }
    }

    class MockCertificateProvider implements CertificateProvider {

        @Override
        public List<X509Certificate> requestCaSignedCertificate(KeyPair keyPair, List<String> domains) {
            return null;
        }
    }

    class MockKeyPairProvider implements KeyPairProvider {

        @Override
        public VersionedKeyPair getKeyPair(ApplicationId applicationId) {
            return null;
        }
    }

    @Test
    public void testEndpointNames() throws URISyntaxException {
        ApplicationId applicationId = ApplicationId.from("tenant", "application", "instance");

        CertificateManager certificateManager = new CertificateManager(new MockCertificateStore(), new MockCertificateProvider(), new MockKeyPairProvider(), new ZoneRegistryMock());

        URI uri = new URI("https://*.tragisk.com");

        certificateManager.endpointNames(applicationId).forEach(System.out::println);
    }
}