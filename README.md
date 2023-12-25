# trifecta
A simple image sharing site, built with a combination of modern c++, database
and web technologies. Intended to both be useful and make some points.

# Goals

 * Provide an easy on-ramp for "C++ people" to using modern web technology
   * Using a non-bloated minimal framework (alpine.js)
 * Showcase modern C++ and build tools (Meson)
   * A Rust version of the backend is very welcome!
   * A Go version of the backend is very welcome!
 * Show how you can build things without 200 dependencies
 * Show you can do so self-contained without tons of infrastructure
 * Build something that is extremely robust and secure and does not need
   monthly updates.
 * Still get high-end features
 * Actually get an image sharing site for your friends/company
   * Does not provide (moderation) infrastructure for uploads by the public
 * Be a template for other projects

Once done, in ~600 lines of C++, this gets you a safe and secure image sharing site
that you could run yourself and forget about. 

# Status & Thanks
Heavy development ongoing!

Many thanks are also due to early users & contributors:

 * Ruben d'Arco
 * Roel van der Made

# Description
You can paste (but not yet drag!) images to trifecta. If you paste an image, a post will be created for it automatically. 

A post can contain multiple images. Each image can have a caption, and each post a title. 

Both images and posts can be public or not. 

# Known problems

 * UI is clunky
 * You can't yet change your password
 * Login emails not yet implemented
 * Security is probably not yet where it should be
 * The code is still a mess and not yet "education clean"

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
./build/trifecta --admin-password=thinkofsomething
```

And you should be in business. It prints out the URL on which you can
contact the service. On first use you'll get some scary looking SQL errors,
these go away once you've uploaded your first image.

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

Or even:
```bash
LDFLAGS=-static meson setup build --prefer-static -Dbuildtype=release -Dcpp-httplib:cpp-httplib_openssl=disabled -Dcpp-httplib:cpp-httplib_brotli=disabled

meson compile -C build/
```

From this it is trivial to create be easy to create a Docker or podman
image:

```bash
strip build/trifecta
podman build -t berthubert/trifecta -f Dockerfile
podman run -p 1234:1234 -v /some/place/local-db/:/local-db berthubert/trifecta 
```
This syntax means:

 * The binary in the container exposes port 1234, expose it to the world as
   1234 as well
 * Containers are immutable, but we'd love to actually retain uploaded
   images. We therefore mount `/some/place/local-db` on your file system to
   `/local-db` in the container
 * You need to add `--admin-password` to the last line to set an admin password. 

To export this image, try:

```bash
podman save localhost/berthubert/trifecta -o trifecta.container
bzip2 trifecta.container
```

This gets you a 2.3 megabyte compressed container you can distribute.

# Inspiration
The SUSE past-o-o pastebin: https://github.com/openSUSE/paste-o-o

cottow's 6paster: https://github.com/cottow/6paster 

Project with similar aims, a webmail solution built on Go and a functional language called Elm:
https://github.com/inbucket/inbucket
