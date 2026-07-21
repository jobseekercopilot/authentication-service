FROM eclipse-temurin:17-jre-alpine@sha256:02320dd4ce20e243dfb915c686089cf9315c763084fafbb12d5c9993aee18b57

ARG APP_UID=10001
ARG APP_GID=10001

LABEL org.opencontainers.image.title="Job Seeker Copilot Authentication Service" \
      org.opencontainers.image.description="Private authentication service runtime" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary"

WORKDIR /app

RUN apk add --no-cache curl \
    && addgroup -S -g "${APP_GID}" app \
    && adduser -S -D -H -u "${APP_UID}" -G app app

# The JAR must be produced by `mvn -B verify` before this build. The Docker
# context deliberately contains only that verified target artifact.
COPY --chown=${APP_UID}:${APP_GID} target/authentication-service-1.0.0.jar app.jar

USER ${APP_UID}:${APP_GID}

EXPOSE 8084

HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=6 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8084/actuator/health >/dev/null || exit 1

STOPSIGNAL SIGTERM

ENTRYPOINT ["java", "-jar", "app.jar"]
