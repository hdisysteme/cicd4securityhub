FROM python:3.9-alpine

#A dd a user with userid 8877 and name nonroot
RUN useradd −u 8877 nonroot

# Run Container as nonroot
USER nonroot

# Install Dependencies
RUN \
    apk update && \
    apk add python3 bash curl jq file coreutils git && \
    pip3 install --upgrade pip && \
    pip3 install boto3 awscli detect-secrets

COPY script.sh /root

# Installs prowler and moves scripts into prowler directory
RUN \
    git clone https://github.com/toniblyx/prowler && \
    mv root/script.sh /prowler

# Runs prowler
WORKDIR /prowler

CMD bash script.sh
