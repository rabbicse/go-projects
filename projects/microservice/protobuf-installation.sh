PB_REL="https://github.com/protocolbuffers/protobuf/releases"
curl -LO $PB_REL/download/v30.2/protoc-30.2-linux-x86_64.zip

unzip protoc-30.2-linux-x86_64.zip -d $HOME/.local

export PATH="$PATH:$HOME/.local/bin"
