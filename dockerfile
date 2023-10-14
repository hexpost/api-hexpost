FROM rust:latest as builder
WORKDIR /usr/src/app
COPY . .
RUN cargo install --path .
EXPOSE 8080
CMD ["cargo", "run"]