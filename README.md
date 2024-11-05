# N4 CPP

C++ version of [n4.py](https://github.com/MikeWang000000/n4)


## Build

```
$ mkdir build && cd build
$ cmake .. -DCMAKE_BUILD_TYPE=Release
$ cmake --build .
```


## Usage


### Server
server (Python):
```
$ python3 n4.py -s
```


server (C++):
```
$ ./n4 -s
```


### Peer

peer A (Python):
```
$ python n4.py -c -h <n4_server_ip>
```

peer B (C++):
```
$ ./n4 -c -h <n4_server_ip>
```




