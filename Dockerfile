# WORK IN PROGRESS
# Use the latest Ubuntu image as the base
FROM ubuntu:latest

# Set a working directory
WORKDIR /vault1337

# Update package lists and install necessary dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the project files into the container
COPY . .

# Set the default command (adjust as needed for your project)
CMD ["bash"]