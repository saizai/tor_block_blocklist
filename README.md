This repository is a list of sites that are known to block Tor, converted into an easy-to-copy ExitPolicy reject list.

The initial list is from https://trac.torproject.org/projects/tor/wiki/org/doc/ListOfServicesBlockingTor

Sites are *only* included if they are *unusable* via Tor. Sites that are read-only, require extra CAPTCHA, no-login (and login isn't essential to using the site), etc should not be included.

Sites can be listed with specific ports to block, e.g. if HTTP is blocked but HTTPS isn't. By default, it'll generate `ExitPolicy reject site.com:*`.

Pull requests welcome!