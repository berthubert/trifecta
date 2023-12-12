# trifecta
A simple image shring site, built with a combination of modern c++, database
and web technologies

# Building
Requires libsqlite3-dev nlohmann-json and crypto++. On Debian derived
systems the following works:

```
apt install libsqlite3-dev nlohmann-json3-dev python3-pip libcrypto++-dev pkg-config
```

In addition, the project requiers a recent version of meson, which you can
get with 'pip3 install meson ninja' or perhaps 'pip install
meson ninja' and only if that doesn't work 'apt install meson'.

Then run:

```
meson setup build
meson compile -C build
./build/serv
```

And you should be in business.
