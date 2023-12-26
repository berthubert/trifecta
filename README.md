# trifecta
A simple image sharing site, built with a combination of modern C++, database
and web technologies. Intended to both be useful and make some points.

# Goals

 * Show how you can build things without [hundreds of dependencies](https://medium.com/graph-commons/analyzing-the-npm-dependency-network-e2cf318c1d0d)
 * Show you can do so self-contained without tons of infrastructure
   * [2.3MB Docker](https://berthub.eu/trifecta/trifecta.docker.bz2)/Podman image, needs nothing else
 * Provide an easy on-ramp for "C++ people" to using modern web technology
   * Using a non-bloated minimal framework (alpine.js)
 * Showcase modern C++ and build tools (Meson)
   * A Rust version of the backend is very welcome!
   * A Go version of the backend is very welcome!
 * Build something that is extremely robust and secure and does not need
   monthly updates.
   * Still get high-end features
 * Actually get an image sharing site for your friends/company
   * Does not provide (moderation) infrastructure for uploads by the public
 * Be a template for other projects

Once done, in ~1000 lines of C++ & Javascript, this will get you a safe and
secure image sharing site that you could run yourself and forget about.

> Note: the security goals have not yet been achieved, heavy development is
> ongoing. There are no known problems though.

# What is the point?
For one, I'd love to have an 'imgur' just for myself, one that does not
monetize me or the viewers of my images.  But I also do not want to host a
giant web based solution with multiple security issues per year.  [Or month](https://www.mandiant.com/resources/blog/supply-chain-node-js). 
I yearn for software like djbdns or qmail that you could trust to not have
gaping security holes all the time.

Fundamentally, there is no way to keep a solution with hundreds (or
thousands) of dependencies secure. Yet, this is what modern web development
has mostly become. 

Trifecta is an attempt to create a useful and reliable piece of software
that also showcases that it is still possible to write small programs with
a much more limited attack surface.

# Status & Thanks
Heavy development ongoing!

Many thanks are also due to early users & contributors:

 * Ruben d'Arco
 * Roel van der Made
 * Peter van Dijk

While having 700 (indirect) dependencies is not good, benefiting from very
good existing software is great:

 * [SQLiteWriter](https://github.com/berthubert/sqlitewrite/) for seamless
   bridge between SQL and JSON, with automated schema generation, [SQLite](https://sqlite.org/)
 * [nlohmann-json](https://github.com/nlohmann/json), great C++ JSON library
 * [Alpine.js](https://alpinejs.dev/), a minimalistic Javascript environment
 * [{fmt}](https://github.com/fmtlib/fmt), excellent string formatting, part of recent C++ standards also
 * [cpp-httplib](https://github.com/yhirose/cpp-httplib), pretty excellent  HTTP library
 * [doctest](https://github.com/doctest/doctest), very nice and fast unit  tests
 * [argparse](https://github.com/p-ranav/argparse), great argument parser
 * [Crypto++](https://www.cryptopp.com/) - only for a baseurl64 encoder right now

# Description
You can paste or drag images to Trifecta. If you upload an image, a post will be created for it automatically. 

A post can contain multiple images. Each image can have a caption, and each post a title. 

Posts can be public or not, or have a timelimit on their public visibility
(not yet hooked up in the UI).

# Known problems

 * UI is clunky
 * You can't change your password yet
 * Login emails not yet implemented
 * Security is probably not yet where it should be
 * The code is still a mess and not yet "education clean"

More low hanging fruit can be found in the [GitHub issues
list](https://github.com/berthubert/trifecta/issues).

# Building
Requires libsqlite3-dev nlohmann-json and crypto++. On Debian derived
systems the following works:

```
apt install libsqlite3-dev nlohmann-json3-dev python3-pip libcrypto++-dev pkg-config
```

In addition, the project requires a recent version of meson, which you can
get with 'pip3 install meson ninja' or perhaps 'pip install
meson ninja' and only if that doesn't work 'apt install meson'.

> The meson in Debian bullseye is very old, and will give you a confusing
> error message about 'git' if you try it. If you [enable
> bullseye-backports](https://backports.debian.org/Instructions/) you can do
> `apt install -t bullseye-backports meson` and get a working one. Or use
> the pip version, which is also great.

Then run:

```
meson setup build
meson compile -C build
./build/trifecta --rnd-admin-password
```

And you should be in business. This creates a random admin password, which
it prints for you. It also prints out the URL on which you can
contact the service. On first use you'll get some scary looking SQL errors,
these go away once you've uploaded your first image.

To do admin things (like create new users), visit /admin.html

To take this into production using nginx (for
letsencrypt, TLS etc), try:

```
upstream backendtrifect {
    server 10.0.0.12:3456 fail_timeout=5s max_fails=3;
}

...

location /trifecta/ {
	rewrite    /trifecta/(.*) /$1 break;
	proxy_pass http://backendtrifect;
	add_header X-Cache-Status $upstream_cache_status;
        client_max_body_size 50M; 
        proxy_set_header X-Real-IP $proxy_protocol_addr;

        add_header X-Cache-Status $upstream_cache_status;
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "same-origin";
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' data:;" always;
}
```

# Distributing binaries, docker etc
To make a more portable binary, try:

```bash
LDFLAGS="-static-libstdc++ -static-libgcc" meson setup build --prefer-static
meson compile -C build/
```

Or even a fully static one:
```bash
LDFLAGS=-static meson setup build --prefer-static -Dbuildtype=release -Dcpp-httplib:cpp-httplib_openssl=disabled -Dcpp-httplib:cpp-httplib_brotli=disabled

meson compile -C build/
```

From this it is trivial to create a Docker or podman image:

```bash
strip build/trifecta
podman build -t berthubert/trifecta -f Dockerfile
```

The [Dockerfile](Dockerfile) is very simple, and worth reading. To export this image, try:

```bash
podman save localhost/berthubert/trifecta -o trifecta.container
bzip2 trifecta.container
```

This gets you a 2.3 megabyte compressed container you can distribute.

To run the image:

```bash
podman run -p 1234:1234 -v /some/place/local-db/:/local-db berthubert/trifecta --rnd-admin-password
```
This syntax means:

 * The binary in the container exposes TCP port 1234, expose it to the world as
   1234 as well
 * Containers are immutable, but we'd love to actually retain uploaded
   images. We therefore mount `/some/place/local-db` on your file system to
   `/local-db` in the container
 * --rnd-admin-password creates an admin user with a random password (which
   it prints for you)

When running with Docker, pass `--init` to `docker run` so that signals are handled correctly.

# Simple Docker build

If you do not want to build `trifecta` yourself to generate a Docker image, use `Dockerfile.full-build`:

```bash
docker build -t berthubert/trifecta -f Dockerfile.full-build .
```

# Inspiration
The SUSE past-o-o pastebin: https://github.com/openSUSE/paste-o-o

cottow's 6paster: https://github.com/cottow/6paster 

Project with similar aims, a webmail solution built on Go and a functional language called Elm:
https://github.com/inbucket/inbucket

