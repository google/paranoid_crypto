# Install bookworm debian image
FROM debian:bookworm

# Create user
RUN useradd -ms /bin/bash paranoid-user

# Update Debian repository
RUN apt update && apt install -y python3 python3-pip python3-pybind11 python3-fpylll python3-gmpy2 protobuf-compiler

# Copy necessary files
COPY --chown=paranoid-user ./ /home/paranoid-user/

# Install package using pip
USER paranoid-user
WORKDIR /home/paranoid-user
# PEP668 is not important in a container, thus use --break-system-packages
RUN python3 -m pip install --break-system-packages .
