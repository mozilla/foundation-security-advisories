# MFSA: Mozilla Foundation Security Advisories

Canonical source for Mozilla Foundation Security Advisories. http://www.mozilla.org/security/announce/

[![Build Status](https://travis-ci.org/mozilla/foundation-security-advisories.svg?branch=master)](https://travis-ci.org/mozilla/foundation-security-advisories)

## Writing new announcements

Announcements are written in [Markdown](http://daringfireball.net/projects/markdown/basics) or [YAML](http://yaml.org/spec/1.1/). They should
be named in the pattern `announce/YYYY/mfsaYYYY-XX.EXT` where `YYYY` is the 4 digit year, `XX` is
the next in the sequence, and `EXT` is either `md` or `yml`. 

### Markdown Format

Once the file is created some data about the file should be added to the
[Front Matter](http://jekyllrb.com/docs/frontmatter/). Front Matter is [YAML](http://yaml.org/spec/1.1/)
encoded data surrounded by lines consisting of 3 dashes. Then the Markdown content can be added below the 
Front Matter. For example:

```markdown
---
announced: April 29, 2014
fixed_in:
- Firefox 29
- Firefox ESR 24.5
- Thunderbird 24.5
- Seamonkey 2.26
impact: High
reporter: Abhishek Arya
title: Buffer overflow when using non-XBL object as XBL
---

### Description

Mozilla community member **James Kitchener** reported a crash in
DirectWrite when rendering MathML content with specific fonts due to an error in
how font resources and tables are handled. This leads to use-after-free of a
DirectWrite font-face object, resulting in a potentially exploitable crash.
```

> **NOTE:** There is no need to include the MFSA ID in the front matter, it will be extracted from the file name.

> **NOTE:** HTML is valid Markdown. So if you need extra features or classes, just add them.

#### Metadata spec

There are some required elements in the Front Matter data (metadata). They are:

```yaml
announced: Date in Month Day, Year format
fixed_in: List of product names and versions (see example above)
impact: one of (Critical, High, Moderate, Low)
reporter: Name of bug reporter
title: Title of the advisory (may contain HTML).
```

Other data will be displayed, but the above will be expected in the template and styled correctly.

> **NOTE:** You should *NOT* add a `products:` section to the data. The list of products is extracted
> from the `fixed_in:` list when imported into the website.

### YAML Format

The YAML type is for advisories that are actually a roll-up of multiple advisories. These files are all YAML
as opposed to the `.md` files which are only partially YAML. The following example should demonstrate the
features of this file type:

```yaml
announced: September 20, 2016
fixed_in:
- Thunderbird 45.4
title: Security vulnerabilities fixed in Thunderbird 45.4
description: |
  Text that will appear at the top of the file. ***Markdown*** allowed.
  
  ### An h3 is sometimes good
  
  Then you can explain further.
advisories:
  CVE-2016-5270:
    title: Heap-buffer-overflow in nsCaseTransformTextRunFactory::TransformString
    impact: high
    reporter: Atte Kettunen
    description: |
      Short description <strong>with HTML</strong> and multiple lines!

      Can also have full breaks and ***markdown***!
    bugs:
      - url: 1291016
        desc: The text for the bug link
  CVE-2016-5272:
    title: Bad cast in nsImageGeometryMixin
    impact: high
    reporter: Abhishek Arya
    description: A bad cast when processing layout with <code>input</code> elements can result in a potentially exploitable crash.
    bugs:
      - url: 1297934
  CVE-2016-5276:
    title: Heap-use-after-free in mozilla::a11y::DocAccessible::ProcessInvalidationList
    impact: high
    reporter: Nils
    description: A use-after-free vulnerability triggered by setting a <code>aria-owns</code> attribute
    bugs:
      - url: 1287721
```

The main part of the data is the same as the front-matter of the `.md` files. The primary difference is the `advisories`
key, which contains a list of CVEs with their individual data. A CVE entry can have a list of bug urls. These can be:

* A bugzilla bug number. These will be converted to a bugzilla link.
* A comma separated list of bug numbers. These will be converted to a link to a bugzilla list of bugs.
* A valid URL will be kept as is.

Along with the `url` field of a bug, a `desc` may optionally be supplied. This will be the link text
for the bug link. If it is not supplied the default is `Bug {url}`. For example, the link text for
the bug in `CVE-2016-5276` above would be `Bug 1287721`.

The main `description` field as well as those of the CVE entries can be multi-line and will be processed
as markdown. The YAML spec provides [different ways of enabling multi-line](http://yaml.org/spec/1.1/#id926836), 
but the best for this application is to use the `|` character after the `:` 
like you see in the example for the main description and `CVE-2016-5270` above.

## Bug Bounty Hall of Fame Files

This repo also contains data that bedrock uses to generate the
[client](https://www.mozilla.org/en-US/security/bug-bounty/hall-of-fame/) and 
[web](https://www.mozilla.org/en-US/security/bug-bounty/web-hall-of-fame/) hall of fame pages.
These are the YAML files in the `bug-bounty-hof` directory. The data format for these YAML files is rather simple. 
The only required field in the file is `names`: this is a list of data structures about each name in the hall of fame. 
For each name entry only `name` and `date` are required. The `date` field must be in the format `YYYY-MM-DD`.
You can optionally add a `url` field and the entry on the page will link to this url. You are free to add other 
data to each entry (e.g. `bug`, `organization`), but at present bedrock will not use these items on the site.

## Linter Script

There is a script in the repo called `check_advisories.py` that will tell you when you've gotten something wrong. It uses
the same parsing algorithm as bedrock and so it should catch errors before they cause problems
on the website. By default it will check all modified advisory and bug bounty files in the repo. If you want
to check them all you can pass the `--all` switch. And if you only want it to check the changes
staged in git's index you can pass the `--staged` switch (this is mostly good for a git pre-commit hook).

You'll need a couple of dependency libraries. You can get them with the following command:

```shell
$ pip install -r requirements.txt
```

It's best to do that within a [virtualenv](http://virtualenv.readthedocs.org/en/latest/).
Then you can run the command:

```shell
$ ./check_advisories.py
Checked 3 files. Found 0 errors.
```

Use the `--help` switch to see all options.

### Use as a git hook

The best way to use this linter script is to add a git pre-commit hook. Included in the repo is a
shell script useful for this purpose. To install it issue the following commands from the root
directory of the repo:

```shell
$ cd .git/hooks && ln -s ../../pre-commit-hook.sh pre-commit
```

After this if you attempt to commit a change to a file that has a problem being parsed, you'll be
informed which file has a problem and the commit will be aborted.

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
