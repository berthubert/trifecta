# trifecta
A simple open source image sharing site, built with a combination of modern C++, database
and web technologies. Intended to both be useful and make some points.

Webpage: [berthub.eu/articles/trifecta](https://berthub.eu/articles/trifecta), including links to blog post detailing "why". 

# Description
Trifecta is a computer program that delivers you a website/web service. Your personal imgur.
You can paste or drag images to Trifecta. If you upload an image, a post will be created for it automatically. 

A post can contain multiple images. Each image can have a caption, and each post a title. 

Posts can be public or not, or have a time limit on their public visibility.
As owner of a post you can extend or change this limit.

Users can sign in using an temporary email link, and also reset their
password this way. Users need not have an actual password.

Posts in Trifecta get opengraph tags so you get nice previews on social
media and in messengers.

Available as docker/podman, rpm, deb and source. 

# Goals

 * Show how you can build things without [hundreds of dependencies](https://medium.com/graph-commons/analyzing-the-npm-dependency-network-e2cf318c1d0d)
 * Show you can do so self-contained without tons of infrastructure
   * Compressed [1.6MB Docker](https://berthub.eu/tmp/trifecta.docker.xz)/Podman image, needs nothing else
 * Provide an easy on-ramp for "C++ people" to using modern web technology
   * Using a non-bloated minimal framework (alpine.js)
 * Showcase modern C++ and build tools (Meson)
   * A Rust, Go, whatever, version of the backend is very welcome!
 * Build something that is extremely robust and secure and does not need
   monthly updates.
   * But still delivers high-end features
 * Actually get an image sharing site for your friends/company
   * Does not provide (moderation) infrastructure for uploads by the public
 * Be a template for other projects

In ~1000 lines of C++ & Javascript, this gets you a safe and
secure image sharing site that you could run yourself and hopefully forget about.

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
Development is still ongoing, but usable. 

Many thanks are also due to early users & contributors:

 * Ruben d'Arco
 * Roel van der Made
 * Peter van Dijk
 * Bryan Seitz

While having 700 (indirect) dependencies is not good, benefiting from very
good existing software is great:

 * [SQLiteWriter](https://github.com/berthubert/sqlitewrite/) for seamless
   bridge between SQL and JSON, with automated schema generation, [SQLite](https://sqlite.org/)
 * [nlohmann-json](https://github.com/nlohmann/json), great C++ JSON library
 * [Alpine.js](https://alpinejs.dev/), a minimalistic Javascript environment
 * [{fmt}](https://github.com/fmtlib/fmt), excellent string formatting, part of recent C++ standards also
 * [cpp-httplib](https://github.com/yhirose/cpp-httplib), pretty excellent HTTP library
 * [doctest](https://github.com/doctest/doctest), very nice and fast unit  tests
 * [argparse](https://github.com/p-ranav/argparse), great argument parser

# Known problems

 * UI is still somewhat clunky
 * Security is probably not quite yet where it should be
 * The code is still not quite yet "education clean"

More low hanging fruit can be found in the [GitHub issues list](https://github.com/berthubert/trifecta/issues).

# Concepts
More about this can be found on the [Trifecta web page](https://berthub.eu/articles/trifecta/).

The software consists of a server process, which provides an API for creating users, posts, images etc. It hosts all these in a single sqlite3 database. The server also hosts a few Javascript and HTML files that provide the frontend. To send out password reset/passwordless login emails, it connects to an SMTP server.

To run the software, put it behind a real webserver that does TLS and certificate management for you. Instructions are in [the README](https://github.com/berthubert/trifecta/blob/main/README.md).

The server configures the sqlite database automatically, there is no need to load a schema. Out of the box, the system is not operational as it has no admin user. If you run the server with `--rnd-admin-password` it will create an admin user with a randomly generated password for you. If you run it again like that it will only change the password.

# Configuration
Configuration is read both from the command line and from the environment:

 * --db-file / TRIFECTA_DB: Path to the sqlite3 database file
 * --html-dir / TRIFECTA_HTML\_DIR: Path to the HTML, CSS, SVG and Javascript files
 * --port / TRIFECTA_PORT: Numerical TCP port on which the webserver will listen
 * --local-address / TRIFECTA_LOCAL: IP(v6) address on which the webserver will listen
 * --smtp-server / TRIFECTA\_SMTP\_SERVER: SMTP server IP:port that allows us to send email
 * --smtp-from / TRIFECTA_MAIL\_FROM: FROM and From address for email to be sent
 * --canonical-url / TRIFECTA\_CAN\_URL: Canonical full URL of the service (for email use)
 
The command line overrides the environment variables.

To get started:

```
trifecta --rnd-admin-password
```

And you should be in business. This creates a random admin password, which
it prints for you. It also prints out the URL on which you can
contact the service. On first use you'll get some scary looking SQL errors,
these go away once you've uploaded your first image.

To do admin things (like create new users), visit /#admin

To take this into production using nginx (for letsencrypt, TLS etc), try:

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
Do know that the default configuration of Trifecta will listen on 127.0.0.1
only, use `-l 0.0.0.0` (or TRIFECTA_LOCAL=0.0.0.0) to change this.

# Podman/Docker
You can get the Docker image by pulling berthubert/trifecta from the Docker
Hub. There is also a Docker-compose file in [example-configs/compose.yaml](example-configs/compose.yaml),
through which you can also configure your container.

If running without Docker-compose, this works both for Podman and Docker:

```bash
docker run --init -p 1234:1234             \
  -v /some/place/local-db/:/local-db       \
  berthubert/trifecta                      \
  --rnd-admin-password
```
This syntax means:

 * --init means you can ^C the container if needed
 * The binary in the container exposes TCP port 1234, expose it to the world as
   1234 as well
 * Containers are immutable, but we'd love to actually retain uploaded
   images. We therefore mount `/some/place/local-db` on your file system to
   `/local-db` in the container
 * --rnd-admin-password creates an admin user with a random password (which
   it prints for you). 

This will exit quickly after creating the admin user.

Next up remove --rnd-admin-password, and start the container again, and you
are in business. 

Note that if you run using the Docker-compose file, there is a 'command'
statement there for --rnd-admin-password which you need to uncomment once.

# Building (optional)
Requires libsqlite3-dev. On Debian derived systems the following works:

```
apt install libsqlite3-dev python3-pip pkg-config
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

This gets you a 2.0 megabyte compressed container you can distribute.

To run the image, run this once:


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
