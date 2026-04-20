FROM alpine:3.20 AS build

RUN apk add --no-cache build-base

WORKDIR /src

RUN mkdir -p /out

COPY src ./src

RUN cc -O2 -fPIE -static-pie -Wall -Wextra -pedantic -std=c11 \
    -o /out/decoy-server \
    src/main.c \
    src/request_parser.c \
    src/response_builder.c \
    src/event_logger.c \
    src/router_profile.c \
    src/nvr_profile.c \
    src/admin_profile.c

FROM scratch

WORKDIR /app

COPY --from=build /out/decoy-server /app/decoy-server
COPY assets /app/assets

EXPOSE 80

CMD ["/app/decoy-server"]
