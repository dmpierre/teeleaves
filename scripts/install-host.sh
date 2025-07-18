# Install the Nitro Enclaves CLI.
sudo dnf install aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel openssl-devel gcc cmake3 gcc-c++ -y

# Add the ec2-user to the ne group.
sudo usermod -aG ne ec2-user

# Add the ec2-user to the docker group.
sudo usermod -aG docker ec2-user

# Check the version of the Nitro Enclaves CLI.
nitro-cli --version

# Enable and start the Nitro Enclaves Allocator service.
sudo systemctl enable --now nitro-enclaves-allocator.service

# Enable and start the docker service.
sudo systemctl enable --now docker

# Install the rust toolchain.
curl https://sh.rustup.rs -sSf | sh -s -- -y

# Source the cargo env.
source $HOME/.cargo/env

# Copy the allocator template to the Nitro Enclaves config directory.
sudo cp allocator.template.yaml /etc/nitro_enclaves/allocator.yaml

# Restart the Nitro Enclaves Allocator service to pick up the new allocator config.
sudo systemctl restart nitro-enclaves-allocator.service
