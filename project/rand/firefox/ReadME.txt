#######Install Way########
xcode-select --install
brew install cmake pkg-config libomp secp256k1

########BUILD Way#################
cd build
rm -rf *
cmake ..
make -j$(sysctl -n hw.logicalcpu)



////////Linux///////
sudo apt install -y build-essential cmake pkg-config libsecp256k1-dev libomp-dev

mkdir -p build && cd build
cmake ..
make -j$(nproc)
