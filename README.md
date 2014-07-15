# MFSA: Mozilla Foundation Security Advisories

Canonical source for Mozilla Foundation Security Advisories. http://www.mozilla.org/security/announce/

## Import Script

`import_html.py` is a script that will convert the Mozilla Foundation Security Announcement HTML (PHP) files from [the SVN repository](http://svn.mozilla.org/projects/mozilla.org/trunk/security/) into markdown snippets suitable for inclusion in [bedrock](https://github.com/mozilla/bedrock/) (the new backend for www.mozilla.org).

### Usage

Checkout the source files from SVN:

    svn checkout http://svn.mozilla.org/projects/mozilla.org/trunk/security/

Then point the script at the directory the above command created:

    ./import-html.py /some/path/to/security

Full usage options are available in the help:

```
$ ./import_html.py -h
usage: import_html.py [-h] [-o OUT] DIR

Import and convert security HTML

positional arguments:
  DIR         Path to "security" directory from mozilla.org SVN.

optional arguments:
  -h, --help  show this help message and exit
  -o OUT      Output directory (default: ./security)
```
