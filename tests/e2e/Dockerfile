FROM rust:1-bookworm
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    iproute2 iputils-ping netcat-openbsd iptables procps pv openssh-client >/dev/null
