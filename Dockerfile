FROM --platform=$BUILDPLATFORM golang:1.22-bookworm AS build
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /loger .

FROM scratch
COPY --from=build /loger /loger
ENTRYPOINT ["/loger"]
CMD ["daemon"]
