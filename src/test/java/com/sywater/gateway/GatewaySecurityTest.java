package com.sywater.gateway;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GatewaySecurityTest {

    static final String ISSUER = "https://iam.cuidatuagua.local";
    static KeyPair keys;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keys = generator.generateKeyPair();

        Path publicPem = Files.createTempFile("iam-public", ".pem");
        Files.writeString(publicPem, "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keys.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n");

        registry.add("gateway.jwt.public-key", () -> "file:" + publicPem.toAbsolutePath());
        registry.add("gateway.jwt.issuer", () -> ISSUER);
        registry.add("gateway.cors.allowed-origins", () -> "http://localhost:8081");
        // No Redis and no services in the tests: the gateway decisions are what we check
        registry.add("spring.data.redis.port", () -> "1");
        registry.add("spring.data.redis.connect-timeout", () -> "200ms");
        for (String service : List.of("iam", "places", "devices", "consumption", "valve", "notifications")) {
            registry.add("services." + service, () -> "http://localhost:1");
        }
    }

    @Value("${local.server.port}")
    int port;

    WebTestClient client;

    @BeforeEach
    void setUp() {
        client = WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    static String token(String issuer, List<String> roles) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(UUID.randomUUID().toString())
                .claim("roles", roles)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claims);
        jwt.sign(new RSASSASigner((RSAPrivateKey) keys.getPrivate()));
        return jwt.serialize();
    }

    @Test
    void protectedRouteWithoutTokenIs401WithProblemJson() {
        client.get().uri("/places/api/places")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().exists("X-Correlation-Id")
                .expectBody().jsonPath("$.title").isEqualTo("auth.invalid_token");
    }

    @Test
    void tokenFromAnotherIssuerIs401() throws Exception {
        client.get().uri("/places/api/places")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token("https://evil.example", List.of("USER")))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void validTokenGoesThroughTheGateway() throws Exception {
        client.get().uri("/places/api/places")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(ISSUER, List.of("USER")))
                .exchange()
                .expectStatus().value(status -> assertThat(status).isNotIn(401, 403, 404));
    }

    @Test
    void loginIsPublic() {
        client.post().uri("/iam/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"a@b.co\",\"password\":\"x\"}")
                .exchange()
                .expectStatus().value(status -> assertThat(status).isNotIn(401, 403, 404));
    }

    @Test
    void googleSignInIsPublic() {
        for (String path : new String[]{"/iam/api/auth/google/status", "/iam/api/auth/google/start?redirect=x",
                "/iam/api/auth/google/callback?code=c&state=s"}) {
            client.get().uri(path)
                    .exchange()
                    .expectStatus().value(status -> assertThat(status).as(path).isNotIn(401, 403, 404));
        }
        client.post().uri("/iam/api/auth/google/exchange")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"code\":\"x\"}")
                .exchange()
                .expectStatus().value(status -> assertThat(status).isNotIn(401, 403, 404));
    }

    @Test
    void adminRouteWithUserRoleIs403() throws Exception {
        client.get().uri("/iam/api/admin/users")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(ISSUER, List.of("USER")))
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.title").isEqualTo("auth.admin_required");
    }

    @Test
    void adminRouteWithAdminRoleGoesThrough() throws Exception {
        client.get().uri("/iam/api/admin/users")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(ISSUER, List.of("ADMIN", "USER")))
                .exchange()
                .expectStatus().value(status -> assertThat(status).isNotIn(401, 403, 404));
    }

    @Test
    void guestLinkReadsArePublic() {
        String token = "A".repeat(43);
        for (String path : new String[]{"/places/api/guest/" + token, "/consumption/api/guest/" + token + "/consumption"}) {
            client.get().uri(path).exchange()
                    .expectStatus().value(status -> assertThat(status).as(path).isNotIn(401, 403, 404));
        }
    }

    @Test
    void guestLinkIsReadOnlyAndEverythingElseStaysProtected() {
        String token = "A".repeat(43);
        // writing through the public path is not allowed
        client.post().uri("/places/api/guest/" + token)
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange()
                .expectStatus().isUnauthorized();
        // the owner's management endpoints keep requiring a token
        client.get().uri("/places/api/places/" + UUID.randomUUID() + "/guest-link").exchange()
                .expectStatus().isUnauthorized();
        client.get().uri("/places/api/places/" + UUID.randomUUID() + "/access").exchange()
                .expectStatus().isUnauthorized();
        client.get().uri("/consumption/api/places/" + UUID.randomUUID() + "/consumption").exchange()
                .expectStatus().isUnauthorized();
        // service-to-service lookups of the guest link are never reachable from outside
        client.get().uri("/places/internal/guest-links/" + token).exchange().expectStatus().isNotFound();
    }

    @Test
    void internalEndpointsAreNotExposed() {
        client.get().uri("/devices/internal/metrics").exchange().expectStatus().isNotFound();
        client.get().uri("/iam/actuator/health").exchange().expectStatus().isNotFound();
    }

    @Test
    void openApiDocumentsAreRoutedWithoutToken() {
        // The services are down in the tests: the gateway must let the request through (not 401/403/404)
        client.get().uri("/places/openapi/v1.json").exchange()
                .expectStatus().value(status -> assertThat(status).isNotIn(401, 403, 404));
        client.get().uri("/iam/v3/api-docs").exchange()
                .expectStatus().value(status -> assertThat(status).isNotIn(401, 403, 404));
    }

    @Test
    void gatewayHealthIsPublic() {
        client.get().uri("/actuator/health").exchange()
                .expectStatus().value(status -> assertThat(status).isIn(200, 503));   // 503 = Redis down in tests
    }

    @Test
    void corsPreflightFromAllowedOriginIsAccepted() {
        client.options().uri("/places/api/places")
                .header(HttpHeaders.ORIGIN, "http://localhost:8081")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:8081");
    }

    @Test
    void corsPreflightFromUnknownOriginIsRejected() {
        client.options().uri("/places/api/places")
                .header(HttpHeaders.ORIGIN, "https://evil.example")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .exchange()
                .expectStatus().isForbidden();
    }
}
