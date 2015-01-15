# MFSA: Mozilla Foundation Security Advisories

Canonical source for Mozilla Foundation Security Advisories. http://www.mozilla.org/security/announce/

## Writing new announcements

Announcements are written in [Markdown](http://daringfireball.net/projects/markdown/basics). They should
be named in the pattern `announce/YYYY/mfsaYYYY-XX.md` where `YYYY` is the 4 digit year, and `XX` is
the next in the sequence. Once the file is created some data about the file should be added to the
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

### Metadata spec

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

## Linter Script

There is a script in the repo called `check_advisories.py` that will tell you when you've gotten something wrong. It uses
the same parsing algorithm as bedrock and so it should catch errors before they cause problems
on the website. By default it will check all modified advisory files in the repo. If you want
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
