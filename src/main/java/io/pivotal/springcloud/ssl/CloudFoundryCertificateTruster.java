/*
 * Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.pivotal.springcloud.ssl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertySource;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Trusts certificates specified by environment variables CF_TARGET and
 * TRUST_CERTS. Trust is established during application context initialization.
 *
 * @author wtran@pivotal.io
 */
public class CloudFoundryCertificateTruster implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    private static final Logger log = LoggerFactory.getLogger(CloudFoundryCertificateTruster.class);
    private SslCertificateTruster sslCertificateTruster = SslCertificateTruster.instance;

    private boolean inited =false;

    /**
     * import trust from cer urls,comma seperated such as   google.com,www.ccc.com:8443
     *
     * @param trustCertUrls
     */
    private void trustCertificatesFromURLInternal(String trustCertUrls) {
        if (trustCertUrls != null) {
            for (String hostAndPort : trustCertUrls.split(",")) {
                String[] parts = hostAndPort.split(":");
                String host = parts[0];
                int port = 443;
                try {
                    port = Integer.parseInt(parts[1]);
                } catch (Exception e) {
                }
                if (host != null && host.length() > 0 && port > 0 && port < 65536) {
                    try {
                        sslCertificateTruster.trustCertificateInternal(host, port, 5000);
                    } catch (Exception e) {
                        log.error("trusting certificate at {}:{} failed", host, port, e);
                    }
                }
            }
        }
    }


    /**
     * import trust from truststore file
     *
     * @param applicationContext
     * @param trustStore
     * @param trustStorePassword
     */
    private void trustCertificatesFromStoreInternal(ConfigurableApplicationContext applicationContext, String trustStore, String trustStorePassword) {
        if (trustStore != null) {
            try {
                KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                keystore.load(applicationContext.getResource(trustStore).getInputStream(), trustStorePassword.toCharArray());
                Enumeration<String> aliases = keystore.aliases();

                List<X509Certificate> certCollect = new ArrayList<X509Certificate>();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();

                    Certificate[] certs = keystore.getCertificateChain(alias);
                    if (certs != null && certs.length > 0)
                        for (Certificate cert : certs)
                            if (cert instanceof X509Certificate)
                                certCollect.add((X509Certificate) cert);

                    Certificate cert = keystore.getCertificate(alias);
                    if (cert != null && cert instanceof X509Certificate) {
                        certCollect.add((X509Certificate) cert);
                    }
                }

                if (certCollect.size() > 0)
                    sslCertificateTruster.appendToTruststoreInternal(certCollect.toArray(new X509Certificate[0]));

            } catch (Exception e) {
                log.error("trusting trustore at {}:{} failed", trustStore, trustStorePassword, e);
            }
        }
    }

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {

        if(!inited) {
            inited = true;
            String trustCertUrls = null;
            String trustStore = null;
            String trustStorePassword = null;

            ConfigurableEnvironment environment = applicationContext.getEnvironment();
            for (PropertySource<?> propertySource : environment.getPropertySources()) {
                if (propertySource.containsProperty("app.ssl.trustStore"))
                    trustStore = (String) propertySource.getProperty("app.ssl.trustStore");
                if (propertySource.containsProperty("app.ssl.trustStorePassword"))
                    trustStorePassword = (String) propertySource.getProperty("app.ssl.trustStorePassword");
                if (propertySource.containsProperty("app.ssl.trustCertUrls"))
                    trustCertUrls = (String) propertySource.getProperty("app.ssl.trustCertUrls");
            }

            if (trustCertUrls != null)
                trustCertificatesFromURLInternal(trustCertUrls);

            if (trustStore != null)
                trustCertificatesFromStoreInternal(applicationContext, trustStore, trustStorePassword);
        }
    }
}