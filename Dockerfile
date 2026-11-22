FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /darban .

FROM scratch
COPY --from=build /darban /darban
USER 65532:65532
ENTRYPOINT ["/darban"]
