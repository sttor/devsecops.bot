FROM aquasec/trivy:0.48.3


RUN apk update && apk add \
 ca-certificates \
 curl \
 gnupg \
 lua5.3 \
 openssl \
 pcre \
 xz \
 zip


# Install Docker
RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-25.0.1.tgz | tar xvz -C /usr/local/bin --strip=1 docker/docker


# Install the AWS CLI
RUN apk update && apk add py3-pip


# Add user 1001
RUN adduser -D -u 1001 user1


# Create the /.docker/ directory and set user 1001 as the owner
RUN mkdir /.docker/ && chown 1001:1001 /.docker/
RUN mkdir /.bin/ && chown 1001:1001 /.bin/
RUN mkdir /output/ && chown 1001:1001 /output/
RUN mkdir /cache/ && chown 1001:1001 /cache/


# Install the syft tool
RUN curl  https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh


# Install the Grype tool
RUN curl https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh


# Set user 1001 as the default user for the container
# Set the working directory to /app
WORKDIR /app


# Install Python and pip
RUN apk add --no-cache python3 py3-pip


# Copy the script and requirements (if needed) into the container
COPY . /app/


# Install required Python packages
RUN pip install requests kubernetes awscli requests  --break-system-packages


USER 1001


ENTRYPOINT []
CMD ["/usr/bin/python3", "run.py"]