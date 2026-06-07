# Stage 1: Build eBPF programs
FROM ubuntu:22.04 as bpf-builder
RUN apt-get update && apt-get install -y clang llvm libbpf-dev make linux-tools-common
COPY bpf/ /bpf/
WORKDIR /bpf
RUN make

# Stage 2: Build Go loader
FROM golang:1.22 as go-builder
COPY loader/ /loader/
COPY --from=bpf-builder /bpf/*.o /loader/
WORKDIR /loader
RUN go build -o beacon-guard .

# Stage 3: Runtime
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libbpf0 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=go-builder /loader/beacon-guard /usr/local/bin/
COPY --from=bpf-builder /bpf/*.o /opt/beacon-guard/bpf/
COPY config.json /app/config.json

ENTRYPOINT ["beacon-guard", "--config", "/app/config.json"]
