# docker build -t bx25s:project --output . --target exports .
FROM debian:bookworm AS build
RUN apt update -y && apt upgrade -y && apt install -y build-essential
COPY bxproject bxproject
RUN rm -f bxproject/vuln
RUN make -C bxproject
FROM scratch AS exports
COPY --from=build bxproject/vuln /vuln
