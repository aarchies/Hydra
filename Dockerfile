# builder
FROM docker.fengchuang.tech/menace/tshark-ubuntu:base AS builder
WORKDIR /temp

ADD ./cmd/offline/ ./cmd/offline/
ADD ./config/ ./config/
ADD ./export/ ./export/
ADD ./internal/ ./internal/
ADD ./pkg/ ./pkg/
ADD ./static/ ./static/
ADD ./utils/ ./utils/
ADD ./main.go .
COPY go.mod .
COPY go.sum .

RUN go env -w GOPROXY=https://goproxy.cn,direct
RUN go build -o libparser.so -buildmode=c-shared main.go
RUN go build -o /temp/offline ./cmd/offline/main.go

# runtime 
FROM docker.fengchuang.tech/menace/tshark-ubuntu:base AS runtime
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
WORKDIR /data

# .so offline    
COPY --from=0 /temp/libparser.so /usr/local/lib/
COPY --from=0 /temp/offline /usr/local/bin/offline
ADD ./include/libparser.h /usr/local/include/

# suricata
RUN apt -y install autoconf automake build-essential cargo \
    cbindgen libjansson-dev libpcap-dev libpcre2-dev libtool \
    libyaml-dev make pkg-config rustc zlib1g-dev liblz4-dev \ 
    libmagic-dev libcap-ng-dev libelf-dev libnet-dev

ADD ./build/suricata-7.0.5.tar.gz .
RUN cp rust/dist/rust-bindings.h /usr/local/include/   

RUN ./configure 
RUN rm -rf src/Makefile && mv src/Makefile.bak src/Makefile && make CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib -lparser" -j10 \
    && make install && cp src/.libs/suricata /usr/local/bin/suricata && ldconfig

RUN make install-conf
RUN rm -rf * .vscode

# 添加entrypoint.sh
COPY ./build/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
# ENTRYPOINT ["tail", "-f", "/dev/null"]