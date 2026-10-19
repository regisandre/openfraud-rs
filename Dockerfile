# Build: docker build -t openfraud .
# Run:   docker run -d --name openfraud -v openfraud-data:/data \
#          -p 8090:8090 -p 127.0.0.1:8091:8091 openfraud
#        docker logs openfraud   (the admin token, at first start)
FROM rust:1-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock openfraud.toml ./
COPY src src
COPY core core
COPY packs packs
COPY data data
COPY ui ui
COPY examples examples
RUN cargo build --release --locked --bin openfraud

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data openfraud \
 && mkdir /data && chown openfraud /data
COPY --from=build /src/target/release/openfraud /usr/local/bin/openfraud
USER openfraud
WORKDIR /data
VOLUME /data
# The configuration, the state file and the database live in /data; the
# first start writes a default configuration there. Both listeners take every
# interface inside the container: publish the admin port on the host's
# loopback only (-p 127.0.0.1:8091:8091).
ENV OPENFRAUD_CONFIG=/data/openfraud.toml \
    OPENFRAUD_BIND=0.0.0.0:8090 \
    OPENFRAUD_ADMIN_BIND=0.0.0.0:8091
EXPOSE 8090 8091
ENTRYPOINT ["openfraud"]
CMD ["serve"]
