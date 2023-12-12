# trifecta
A simple image shring site, built with a combination of modern c++, database
and web technologies

# Goals

 * Provide an easy on-ramp for "C++ people" to using modern web technology
 * Showcase modern C++ and build tools (Meson)
   * A Rust version of the backend is very welcome!
 * Show how you can build things without 200 dependencies
 * Show you can do so self-contained without tons of infrastructure
 * Still get high-end features
 * Actually get an image sharing site for your friends/company
 * Be a template for other projects

Once done, in ~600 lines of C++, this gets you a safe and secure image sharing site
that you could run yourself and forget about. 

# Status
Heavy development ongoing!

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
