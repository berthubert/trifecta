FROM ubuntu AS builder
RUN apt update -yqq && apt install -yqq build-essential git \
    libsqlite3-dev nlohmann-json3-dev python3-pip libcrypto++-dev pkg-config
COPY . /project
WORKDIR /project
RUN pip3 install meson ninja
RUN meson setup build
RUN meson compile -C build

FROM scratch
COPY --from=builder /project/build/trifecta trifecta
COPY --from=builder /project/html html
VOLUME /local-db

EXPOSE 1234
ENTRYPOINT ["/trifecta", "-p", "1234","/local-db/trifecta.sqlite"]