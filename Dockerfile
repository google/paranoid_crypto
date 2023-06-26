# Install latest debian image
FROM debian:latest

# Create user
RUN useradd -ms /bin/bash paranoid-user

# Update Debian repository
RUN apt update && apt install -y python3 python3-pip python3-pybind11 python3-fpylll libgmp-dev protobuf-compiler

# Copy necessary files
COPY ./ /home/paranoid-user/

# Install package using pip
USER paranoid-user
WORKDIR /home/paranoid-user
RUN python3 -m pip install .
