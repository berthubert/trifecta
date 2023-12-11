# trifecta
A simple image shring site, built with a combination of modern c++, database
and web technologies

# Building
Requires meson and g++. 

To get meson, you can try 'pip install meson' or perhaps 'pip3
install meson' or if that doesn't work 'apt install meson'.

Then run:

```
meson setup build
meson compile -C build
./build/serv
```

And you should be in business.
