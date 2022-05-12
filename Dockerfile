FROM alpine as build-env
RUN apk add --no-cache build-base && apk add openssl-dev
WORKDIR /app
COPY rsa.c .
RUN gcc -o rsa rsa.c -lcrypto

FROM alpine
COPY --from=build-env /app/rsa .
ENTRYPOINT ["./rsa"]