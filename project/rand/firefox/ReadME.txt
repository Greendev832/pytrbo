cd build
rm -rf *
cmake ..
make -j$(sysctl -n hw.logicalcpu)