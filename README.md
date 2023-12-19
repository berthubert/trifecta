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

 * You can only paste files right now, not drag and drop
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
./build/serv --admin-password=thinkofsomething
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

# Inspiration
The SUSE past-o-o pastebin: https://github.com/openSUSE/paste-o-o

cottow's 6paster: https://github.com/cottow/6paster 

