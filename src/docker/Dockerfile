FROM alpine:3.14.2

# Install Dependencies
RUN \
    apk update && \
    apk add python3 bash curl jq file coreutils git && \
    pip3 install --upgrade pip && \
    pip3 install boto3 awscli detect-secrets

COPY ./src/docker/script.sh /root

# Installs prowler and moves scripts into prowler directory
RUN \
    git clone https://github.com/toniblyx/prowler && \
    mv root/script.sh /prowler

# Create a user group 'prowlergroup'
RUN addgroup -S prowlergroup

# Create a user 'prowleruser' under 'prowlergroup'
RUN adduser -S -D -h /prowler prowleruser prowlergroup

# Chown all the files to the app user.
RUN chown -R prowleruser:prowlergroup /prowler

# Switch to 'appuser'
USER prowleruser

# Runs prowler
WORKDIR /prowler

CMD bash script.sh
