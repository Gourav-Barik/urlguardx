# ---------- STAGE 1: Build ----------
FROM maven:3.9.9-eclipse-temurin-17 AS builder

WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline

COPY src ./src
RUN mvn clean package -DskipTests


# ---------- STAGE 2: Runtime ----------
FROM eclipse-temurin:17-jdk-jammy

WORKDIR /app

# Optional but useful for debugging DB/network
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy built jar
COPY --from=builder /app/target/*.jar app.jar

# Expose port (Render uses $PORT)
EXPOSE 10000

# Run app
ENTRYPOINT ["java", "-jar", "app.jar"]