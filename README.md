# MPSU


## Build
```
git clone https://github.com/secretflow/spu.git
cd spu/examples/
git clone https://github.com/ShallMate/MPSU.git
cd ..
bazel build --linkopt=-ldl //...
cd bazel-bin/examples/mpsu
./mpsu
```

## Result overview
![Result of our work](./example.png)

## NOTE

If you encounter any problems when using this repository, you can ask questions about the issues or contact me directly at gw_ling@sjtu.edu.cn. 
