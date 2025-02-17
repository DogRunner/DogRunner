################################################################ 
# Develop
################################################################ 
FROM golang:1.22.1 as develop
ENV TZ=Asia/Tokyo

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
ENV ROOTPATH=/app
ENV PATH=$PATH:/go/bin/linux_amd64

WORKDIR ${ROOTPATH}

RUN go install github.com/go-delve/delve/cmd/dlv@latest
RUN go install github.com/air-verse/air@v1.52.3
COPY go.mod go.sum .air.toml ./
RUN go mod download
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

COPY . .
EXPOSE 8080

CMD ["air", "-c", ".air.toml"]
# CMD ["sh", "-c", "sleep 3600"] # debug用

# ============
# Builder
# ============
# FROM golang:1.22.1 AS Builder

# ENV CGO_ENABLED=0
# ENV GOOS=linux
# ENV GOARCH=amd64

# WORKDIR /go
# # ENV GO111MODULE=on

# RUN groupadd -g 10001 wanrun \
#     && useradd -u 10001 -g wanrun wanrun

# # Goモジュールのダウンロード
# COPY go.mod ./
# COPY go.sum ./
# RUN go mod download

# COPY . .
# WORKDIR /go/cmd/wanrun

# RUN go build \
# -o main \
# -ldflags '-s -w' \
# main.go

################################################################ 
# Deploy
################################################################ 
FROM --platform=arm64 amazonlinux:2023.6.20250203.1 AS deploy
ENV TZ=Asia/Tokyo

WORKDIR /go
RUN dnf install -y tzdata shadow-utils && \
        rm -rf /var/cache/dnf/*

RUN groupadd -g 10001 wanrun \
    && useradd -u 10001 -g wanrun wanrun

COPY main .

EXPOSE 8080

USER wanrun

ENTRYPOINT ["./main"]
