package com.yahoo.vespa.hosted.controller.certificates;

import com.yahoo.config.provision.ApplicationId;
import com.yahoo.config.provision.ClusterSpec;
import com.yahoo.config.provision.RotationName;
import com.yahoo.security.SubjectAlternativeName;
import com.yahoo.security.X509CertificateUtils;
import com.yahoo.vespa.hosted.controller.api.integration.certificates.ApplicationCertificate;
import com.yahoo.vespa.hosted.controller.api.integration.certificates.CertificateProvider;
import com.yahoo.vespa.hosted.controller.api.integration.certificates.KeyPairProvider;
import com.yahoo.vespa.hosted.controller.api.integration.zone.ZoneRegistry;
import com.yahoo.vespa.hosted.controller.application.Endpoint;
import org.jetbrains.annotations.NotNull;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CertificateManager {

    public CertificateManager(CertificateStore certificateStore,
                              CertificateProvider certificateProvider,
                              KeyPairProvider keyPairProvider,
                              ZoneRegistry zoneRegistry) {
        this.certificateStore = certificateStore;
        this.certificateProvider = certificateProvider;
        this.keyPairProvider = keyPairProvider;
        this.zoneRegistry = zoneRegistry;
    }

    private final CertificateStore certificateStore;
    private final CertificateProvider certificateProvider;
    private final KeyPairProvider keyPairProvider;
    private final ZoneRegistry zoneRegistry;

    private static final Logger log = Logger.getLogger(CertificateManager.class.getName());

    ApplicationCertificate getCertificate(ApplicationId applicationId) {

        ApplicationCertificate currentCertificate = certificateStore.getCertificate(applicationId);
        List<String> domains = endpointNames(applicationId);

        if (currentCertificate == null ||
                tooOld(endIdentityCertificate(currentCertificate)) ||
                !hasNames(domains, endIdentityCertificate(currentCertificate))) {

            return provisionNewAppCert(applicationId, domains);
        }

        return currentCertificate;
    }

    @NotNull
    private ApplicationCertificate provisionNewAppCert(ApplicationId applicationId, List<String> domains) {
        var keyPair = keyPairProvider.getKeyPair(applicationId);
        var newCertificate = certificateProvider.requestCaSignedCertificate(keyPair.keyPair(), domains);
        var newAppCertificate = new ApplicationCertificate(newCertificate, keyPair.keyId());
        certificateStore.storeCertificate(applicationId, newAppCertificate);
        return newAppCertificate;
    }

    private boolean hasNames(List<String> domains, X509Certificate endIdentityCertificate) {
        Set<String> certDomains =
                X509CertificateUtils.getSubjectAlternativeNames(endIdentityCertificate).stream()
                        .filter(san -> san.getType().equals(SubjectAlternativeName.Type.DNS_NAME))
                        .map(SubjectAlternativeName::getValue)
                        .collect(Collectors.toSet());

        return certDomains.containsAll(domains);
    }

    List<String> endpointNames(ApplicationId applicationId) {
        return Stream.concat(
                Stream.of(
                        Endpoint.of(applicationId).target(RotationName.from("default")),
                        Endpoint.of(applicationId).wildcardRotationTarget()
                ),
                zoneRegistry.zones().reachable().ids().stream()
                        .flatMap(zoneId -> Stream.of(
                                Endpoint.of(applicationId).wildcardZoneTarget(zoneId),
                                Endpoint.of(applicationId).target(ClusterSpec.Id.from("default"), zoneId)
                        )))
                .map(builder -> builder.directRouting().on(Endpoint.Port.tls()).in(zoneRegistry.system()))
                .map(Endpoint::dnsName)
                .collect(Collectors.toList());
    }

    private boolean tooOld(X509Certificate certificate) {
        try {
            var inThirtyDays = Date.from(Instant.now().plus(30, ChronoUnit.DAYS));
            certificate.checkValidity(inThirtyDays);
        } catch (CertificateNotYetValidException ignored) {
        } catch (CertificateExpiredException tooOld) {
            return true;
        }
        return false;
    }

    private X509Certificate endIdentityCertificate(ApplicationCertificate applicationCertificate) {
        var certChain = applicationCertificate.certificateChain();
        return certChain.get(certChain.size() - 1);
    }
}
