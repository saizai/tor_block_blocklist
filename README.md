This repository is a list of sites that are known to block Tor, converted into an [easy-to-copy ExitPolicy reject list](https://raw.githubusercontent.com/saizai/tor_block_blocklist/master/blocklist.txt).

To use:

1. git clone https://github.com/saizai/tor_block_blocklist
2. edit torrc to add:  %include /path/to/tor_block_blocklist/blocklist.txt  ([requires tor 0.3.1.7+](https://github.com/torproject/tor/commit/ba3a5f82f11388237a3ba4995ddf0b6ffaaf492a))

The initial list is from the [TorProject wiki](https://trac.torproject.org/projects/tor/wiki/org/doc/ListOfServicesBlockingTor).

Sites that are usable via Tor with limitations — e.g. read-only, requiring extra CAPTCHA, no-login (where login isn't essential to using the site), etc. should *not* be included in this list. It should only list sites that are *unusable* via Tor.

Sites can be listed with specific ports to block, e.g. if HTTP is blocked but HTTPS isn't. By default, it'll generate `ExitPolicy reject site.com:*`.

Pull requests welcome!
