# ── Build stage: compile the jar with Maven ─────────────────────────────────────
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B -DskipTests package

# ── Run stage: only the JRE and the jar ─────────────────────────────────────────
FROM eclipse-temurin:21-jre
WORKDIR /app
RUN useradd --system --no-create-home gateway
COPY --from=build /src/target/api-gateway-*.jar app.jar
USER gateway
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
