#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

version = "0.1"

import os
import sys
import json
import csv
import re
import xml.dom.minidom as minidom
from datetime import date

# https://www.mozilla.org/en-US/security/advisories/mfsa2015-71/
urlbase = "https://www.mozilla.org/en-US/security/advisories"

#############################################################################################################

class BugzillaUrl(object):
    """ Bug link formats:
    - https://bugzilla.mozilla.org/buglist.cgi?bug_id=1138199,1036515,1137326
    - https://bugzilla.mozilla.org/show_bug.cgi?id=1086145
    - BROKEN: https://bugzilla.mozilla.org/buglist.cgi?bug_id=768313,&#10;762920 (fixed)
    """

    base_uri = "https://bugzilla.mozilla.org"

    # TODO: support bugzil.la URLs

    def __init__(self, url=None, bugs=[]):
        self.original_url = url
        self.bugs = bugs
        if self.original_url is not None:
            self.bugs = self.parse(self.original_url)

    @staticmethod
    def parse(url):
        if not url.startswith(BugzillaUrl.base_uri):
            raise Exception("Unsupported Bugzilla base URI in %s" % url)
        args = url.split("?")[1]
        if args.startswith("id="):
            # split off optional comment anchor
            id = args[3:].split("#")[0]
            return [int(id)]
        elif args.startswith("bug_id="):
            bugs = args[7:].split(",")
            # test for known broken urls
            for i in xrange(len(bugs)):
                while bugs[i].startswith(" "):  # Fixes linebreaks within hrefs
                    bugs[i] = bugs[i][1:]
                while bugs[i].endswith(" "):
                    bugs[i] = bugs[i][:-1]
                if not bugs[i].isdigit():
                    raise Exception("Broken Bugzilla bug ID %s in %s" % (bugs[i], url))
                bugs[i] = int(bugs[i])
            return bugs
        else:
            raise Exception("Unsupported Bugzilla CGI script in %s" % url)

    def __str__(self):
        if len(self.bugs) == 0:
            return None
        elif len(self.bugs) == 1:
            script = "show_bug.cgi"
            args = "id=%s" % str(self.bugs[0])
        else:
            script = "buglist.cgi"
            args = "bug_id=%s" % ",".join([str(x) for x in self.bugs])
        return "%s/%s?%s" % (self.base_uri, script, args)

#############################################################################################################

class MfsaMd(object):
    """Class to hold a advisory markdown object
    """
    def __init__(self, mdtxt=None):
        if mdtxt is None:
            self.original_md = None
            self.header = {}
            self.body = minidom.parseString(MfsaMd.xmlheader + MfsaMd.xmlfooter)
        else:
            self.original_md = mdtxt
            self.header, self.body = self.parser(mdtxt)

    """ Anatonomy of a standard MFSA md file:
    ---
    announced: July 2, 2015
    fixed_in:
    - Firefox 39
    - Firefox ESR 31.8
    - Firefox ESR 38.1
    - Thunderbird 38.1
    impact: Critical
    reporter: Mozilla Developers
    title: Miscellaneous memory safety hazards (rv:39.0 / rv:31.8 / rv:38.1)
    ---

    <h3>Description</h3>

    <p>...</p>...

    <h3>Workaround</h3>

    <p>...</p>...

    <h3>References</h3>

    <p>Bob Clary and Andrew McCreight reported memory safety problems and crashes that
    affect Firefox ESR 31.7, Firefox ESR 38, and Firefox 38.</p>

    <ul>
        <li><a href="https://bugzilla.mozilla.org/buglist.cgi?bug_id=1160884,1143679,1164567,1154876">
        Memory safety bugs fixed in Firefox ESR 31.8, Firefox 38.1, and Firefox 39.</a> (<a
        href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2724"
        class="ex-ref">CVE-2015-2724</a>)</li>
    </ul>

    <p>... reported ...</p>

    <ul>...</ul>
    """

    """ Advisories may skip "reporter" header field, "References" line (mangling the links
    into the description), and "Workaround" section.
    """

    """ Known to use non-standard formatting:
    announce/2005/mfsa2005-58.md
    announce/2011/mfsa2011-29.md
    announce/2011/mfsa2011-30.md
    announce/2011/mfsa2011-31.md
    announce/2011/mfsa2011-32.md
    announce/2011/mfsa2011-33.md
    announce/2011/mfsa2011-34.md
    announce/2011/mfsa2011-35.md
    """

    # non-xml entities must be declared explicitly for minidom parsing to work
    # see http://www.w3.org/MarkUp/html-spec/html-spec_14.html
    xmlheader = """<?xml version="1.1" ?>
        <!DOCTYPE htmlxml [
            <!ENTITY nbsp   "&#160;">
            <!ENTITY iexcl  "&#161;">
            <!ENTITY cent   "&#162;">
            <!ENTITY pound  "&#163;">
            <!ENTITY curren "&#164;">
            <!ENTITY yen    "&#165;">
            <!ENTITY brvbar "&#166;">
            <!ENTITY sect   "&#167;">
            <!ENTITY uml    "&#168;">
            <!ENTITY copy   "&#169;">
            <!ENTITY ordf   "&#170;">
            <!ENTITY laquo  "&#171;">
            <!ENTITY not    "&#172;">
            <!ENTITY shy    "&#173;">
            <!ENTITY reg    "&#174;">
            <!ENTITY macr   "&#175;">
            <!ENTITY deg    "&#176;">
            <!ENTITY plusmn "&#177;">
            <!ENTITY sup2   "&#178;">
            <!ENTITY sup3   "&#179;">
            <!ENTITY acute  "&#180;">
            <!ENTITY micro  "&#181;">
            <!ENTITY para   "&#182;">
            <!ENTITY middot "&#183;">
            <!ENTITY cedil  "&#184;">
            <!ENTITY sup1   "&#185;">
            <!ENTITY ordm   "&#186;">
            <!ENTITY raquo  "&#187;">
            <!ENTITY frac14 "&#188;">
            <!ENTITY frac12 "&#189;">
            <!ENTITY frac34 "&#190;">
            <!ENTITY iquest "&#191;">
            <!ENTITY Agrave "&#192;">
            <!ENTITY Aacute "&#193;">
            <!ENTITY Acirc  "&#194;">
            <!ENTITY Atilde "&#195;">
            <!ENTITY Auml   "&#196;">
            <!ENTITY Aring  "&#197;">
            <!ENTITY AElig  "&#198;">
            <!ENTITY Ccedil "&#199;">
            <!ENTITY Egrave "&#200;">
            <!ENTITY Eacute "&#201;">
            <!ENTITY Ecirc  "&#202;">
            <!ENTITY Euml   "&#203;">
            <!ENTITY Igrave "&#204;">
            <!ENTITY Iacute "&#205;">
            <!ENTITY Icirc  "&#206;">
            <!ENTITY Iuml   "&#207;">
            <!ENTITY ETH    "&#208;">
            <!ENTITY Ntilde "&#209;">
            <!ENTITY Ograve "&#210;">
            <!ENTITY Oacute "&#211;">
            <!ENTITY Ocirc  "&#212;">
            <!ENTITY Otilde "&#213;">
            <!ENTITY Ouml   "&#214;">
            <!ENTITY times  "&#215;">
            <!ENTITY Oslash "&#216;">
            <!ENTITY Ugrave "&#217;">
            <!ENTITY Uacute "&#218;">
            <!ENTITY Ucirc  "&#219;">
            <!ENTITY Uuml   "&#220;">
            <!ENTITY Yacute "&#221;">
            <!ENTITY THORN  "&#222;">
            <!ENTITY szlig  "&#223;">
            <!ENTITY agrave "&#224;">
            <!ENTITY aacute "&#225;">
            <!ENTITY acirc  "&#226;">
            <!ENTITY atilde "&#227;">
            <!ENTITY auml   "&#228;">
            <!ENTITY aring  "&#229;">
            <!ENTITY aelig  "&#230;">
            <!ENTITY ccedil "&#231;">
            <!ENTITY egrave "&#232;">
            <!ENTITY eacute "&#233;">
            <!ENTITY ecirc  "&#234;">
            <!ENTITY euml   "&#235;">
            <!ENTITY igrave "&#236;">
            <!ENTITY iacute "&#237;">
            <!ENTITY icirc  "&#238;">
            <!ENTITY iuml   "&#239;">
            <!ENTITY eth    "&#240;">
            <!ENTITY ntilde "&#241;">
            <!ENTITY ograve "&#242;">
            <!ENTITY oacute "&#243;">
            <!ENTITY ocirc  "&#244;">
            <!ENTITY otilde "&#245;">
            <!ENTITY ouml   "&#246;">
            <!ENTITY divide "&#247;">
            <!ENTITY oslash "&#248;">
            <!ENTITY ugrave "&#249;">
            <!ENTITY uacute "&#250;">
            <!ENTITY ucirc  "&#251;">
            <!ENTITY uuml   "&#252;">
            <!ENTITY yacute "&#253;">
            <!ENTITY thorn  "&#254;">
            <!ENTITY yuml   "&#255;">
        ]>
        <html>"""
    xmlfooter = '</html>'

    @staticmethod
    def parser(txt):
        sections = txt.split("---\n")
        if len(sections) != 3 or len(sections[0]) != 0:
            raise Exception("Invalid MFSA format: \n%s\n..." % txt[:300])
        head,bod = sections[1:3]
        header = {}
        append_to = None
        for line in head.split('\n')[:-1]:  # head ends in \n, skip that with [:-1]
            if line.startswith("announced: "):
                header["announced"] = line[11:]
                append_to = None
            elif line.startswith("fixed_in:"):
                if len(line) > len("fixed_in:") + 2:
                    header["fixed_in"] = [line[10:]]
                else:
                    header["fixed_in"] = []
                append_to = "fixed_in"
            elif line.startswith("vulnerable:"):    # TODO: warn about obsolete field
                if len(line) > len("vulnerable:") + 2:
                    header["vulnerable"] = [line[12:]]
                else:
                    header["vulnerable"] = []
                append_to = "vulnerable"
            elif line.startswith("- "):  # fixed_in: or vulnerable: continuation
                # CAVE: "- ..." lines are treated independent of their position
                header[append_to].append(line[2:])
            elif line.startswith("impact: "):
                header["impact"] = line[8:]
                append_to = None
            elif line.startswith("reporter: "):
                header["reporter"] = line[10:]
                append_to = None
            elif line.startswith("title: "):
                header["title"] = line[7:]
                append_to = None
            elif line.startswith("  "):  # title: continuation
                # CAVE: Only supports title continuation, fails silently when other
                # fields are continued like this.
                header["title"] += line[1:]
            elif line.startswith("risk: "):  # TODO: warn about obsolete field
                header["risk"] = line[6:]
                append_to = None
            else:
                raise Exception("Unknown MFSA header: %s" % line)

        # body = minidom.parseString("<html>" + bod + "</html>")
        body = minidom.parseString(MfsaMd.xmlheader + bod + MfsaMd.xmlfooter)

        return header, body

    def __str__(self):
        header = self.header  # TODO: does this make a deep copy?
        header["fixed_in"] =  "\n- ".join(header["fixed_in"])
        header = ["%s: %s" % (k, header[k]) for k in header]  # CAVE: does not maintain order
        header = "\n".join(header) + "\n"
        header.replace("fixed_in: \n", "fixed_in:\n")

        body = ""
        for node in self.body.childNodes[1].childNodes:
            body += node.toprettyxml(indent="  ")
        #assert body.startswith(self.xmlheader)
        #assert body.endswith(self.xmlfooter)
        #body = body[len(self.xmlheader):-len(self.xmlfooter)]

        return "---\n".join(["", header, body])

    def bugLinks(self):
        # TODO: also extract link text for bug titles
        all_links = self.body.getElementsByTagName("a")
        all_hrefs = [a.attributes["href"].value for a in all_links]
        just_buglinks = [h for h in all_hrefs if h.startswith("https://bugzilla.mozilla.org/")]
        return just_buglinks

    def bugRefs(self):
        bugs = []
        for href in self.bugLinks():
            bugs += BugzillaUrl(href).bugs
        return bugs

    def addFixedinToOriginal(self, version):
        input = self.original_md.split("\n")
        output = []
        nothing_added = True
        already_added = False
        i = 0
        while i < len(input):
            line = input[i]
            if line.startswith("fixed_in:"):
                output.append("fixed_in:")
                if len(line) > len("fixed_in:   "):
                    fixversion = line[10:]
                    already_added = fixversion.endswith(version) or already_added
                    while fixversion.startswith(" "):
                        fixversion = fixversion[1:]
                    output.append("- %s" % fixversion)
                while i < len(input)-1 and input[i+1].startswith("- "):
                    already_added = input[i+1].endswith(version) or already_added
                    output.append(input[i+1])
                    i += 1
                if not already_added:
                    output.append("- %s" % version)
                else:
                    print >>sys.stderr, "WARNING: '%s' already marked 'fixed_in'" % version
                nothing_added = False
            else:
                output.append(line)
            i += 1
        if nothing_added:
            raise Exception("Could not add to fixed_in header")
        return "\n".join(output)


#############################################################################################################

class MfsaDB(object):

    def __init__(self, path="announce"):
        self.path = path
        self.tree = [x for x in os.walk(self.path)]
        try:
            assert self.tree[0][1][0] == "2005"
            assert len(self.tree) == len(self.tree[0][1]) + 1
        except AssertionError as e:
            raise Exception("Unknown advisory tree format, reason %s" % e)

    def listYears(self):
        return self.tree[0][1]

    @staticmethod
    def asInts(mfsa_name):
        assert mfsa_name.lower().startswith("mfsa")
        if mfsa_name.lower().endswith(".md"):
            mfsa_name = mfsa_name[:-3]
        year, nr = map(int, mfsa_name[4:].split("-")[0:2])
        return year, nr

    @staticmethod
    def asInt(mfsa_name):
        year, nr = MfsaDB.asInts(mfsa_name)
        # CAVE: don't write more than 999 advisories per year
        return 1000 * year + nr

    @staticmethod
    def nameFromInts(year, nr):
        return "mfsa%04d-%02d" % (year, nr)

    def filenameFromInts(self, year, nr):
        return "%s/%d/mfsa%04d-%02d.md" % (self.path, year, year, nr)

    def filenameFromName(self, mfsa_name):
        year, nr = self.asInts(mfsa_name)
        filename = self.filenameFromInts(year, nr)
        return filename

    @staticmethod
    def isAnewerB(a, b):
        return MfsaDB.asInt(a) > MfsaDB.asInt(b)

    def latestAdvisory(self, year=None, plus=0):
        if year is None:
            # deliver latest advisory in current year + n
            year = date.today().year
        try:
            latest = self.listAdvisories(year)[-1]
            y, n = self.asInts(latest)
        except IndexError:
            y, n = year, 0
            if plus == 0:
                return None
        return self.nameFromInts(year, n + plus)

    def listAdvisories(self, year=None):
        ret = []
        for dirpath, dirnames, filenames in self.tree[1:]:
            if year is None or dirpath.startswith("%s/%04d" % (self.path, year)):
                ret += [x[:-3] for x in filenames if x.startswith("mfsa") and x.endswith(".md")]
        ret.sort(key=MfsaDB.asInt)
        return ret

    def getAdvisory(self, mfsa_name):
        filename = self.filenameFromName(mfsa_name)
        with open(filename, "rb") as f:
            return f.read()

    def writeAdvisory(self, mfsa_name, mfsa):
        filename = self.filenameFromName(mfsa_name)
        content = str(mfsa)
        with open(filename, "wb") as f:
            f.write(content)

    def advisoryInfo(self, name):
        adv = MfsaMd(self.getAdvisory(name))
        return {"name": name, "header": adv.header, "bugs": adv.bugRefs()}

    def allAdvisoryInfo(self):
        ret = []
        return [self.advisoryInfo(name) for name in self.listAdvisories()]

    def bugsToAdvisories(self):
        ret = {}
        for adv in self.allAdvisoryInfo():
            for bugid in adv["bugs"]:
                bugid = int(bugid)
                if bugid in ret:
                    ret[bugid].append(adv["name"])
                else:
                    ret[bugid] = [adv["name"]]
        return ret

#############################################################################################################

class BugzillaSecurityCSV(object):
    def __init__(self, filename):
        self.csv = self.dictFromCsvFile(filename)

    @staticmethod
    def dictFromCsvFile(filename):
        ret = {}
        with open(filename, "rb") as f:
            header = None
            for line in csv.reader(f):
                if header is None:
                    header = line
                else:
                    bug_id = line[0]
                    ret[bug_id] = dict(zip(header[1:], line[1:]))
        return ret

#############################################################################################################

def wrapIntoAdvisoryStub(bugid, csvitem):
    advisory = MfsaMd()
    advisory.header["announced"] = "July 20, 2015"
    advisory.header["title"] = csvitem["Summary"]
    advisory.header["reporter"] = csvitem["Reporter Real Name"]
    advisory.header["fixed_in"] = ["Firefox OS 2.2"]
    impact = "Unrated"
    if "sec-low" in csvitem["Keywords"]:
        impact = "Low"
    if "sec-moderate" in csvitem["Keywords"]:
        impact = "Moderate"
    if "sec-high" in csvitem["Keywords"]:
        impact = "High"
    if "sec-critical" in csvitem["Keywords"]:
        impact = "Critical"
    advisory.header["impact"] = impact

    root = advisory.body
    html = root.childNodes[1]

    desc = root.createElement("h3")
    desc.appendChild(root.createTextNode("Description"))
    html.appendChild(desc)

    p = root.createElement("p")
    p.appendChild(root.createTextNode("TODO: Write a description"))
    html.appendChild(p)

    refs = root.createElement("h3")
    refs.appendChild(root.createTextNode("References"))
    html.appendChild(refs)

    ul = root.createElement("ul")
    html.appendChild(ul)

    bugs = [[bugid, csvitem["Summary"]]]
    # TODO: for every bug: append li with bugzilla link
    for id, title in bugs:
        href = str(BugzillaUrl(bugs=[id]))
        li = root.createElement("li")
        a = root.createElement("a")
        a.setAttribute("href", href)
        a.appendChild(root.createTextNode(title))
        li.appendChild(a)
        ul.appendChild(li)

    return advisory


def advisoryRoundup(opt):
    adv = MfsaDB()
    csv = BugzillaSecurityCSV(opt.bugcsv)

    bug_to_advisory = adv.bugsToAdvisories()
    next_offset = 1
    needs_advisory = []
    needs_fixedin = []
    dangling_bugs = []

    for bugid in csv.csv:
        whiteboard = csv.csv[bugid]["Whiteboard"]
        has_adv_tag = re.search(r'\[adv-[^\]]+\+]', whiteboard) is not None
        has_b2g_adv_tag = re.search(r'\[b2g-adv-[^\]]+\+]', whiteboard) is not None
        #print bugid, has_adv_tag, has_b2g_adv_tag, whiteboard
        if not has_adv_tag:
            new_mfsa_txt = str(wrapIntoAdvisoryStub(bugid, csv.csv[bugid]))
            new_mfsa_name = adv.latestAdvisory(plus=next_offset)
            next_offset += 1
            filename = "TODO/"+adv.filenameFromName(new_mfsa_name)
            print "bug %s needs advisory: %s" % (bugid, filename)
            if not opt.dryrun:
                if not os.path.isdir(os.path.dirname(filename)):
                    os.makedirs(os.path.dirname(filename))
                with open(filename, "wb") as f:
                    f.write(new_mfsa_txt)
            else:
                print >>sys.stderr, "WARNING: skipping write to %s" % filename
            needs_advisory.append(bugid)
        else:
            try:
                print "bug %s has advisory %s" % (bugid, bug_to_advisory[int(bugid)])
                print "TODO: add 'fixed_in: %s' to %s" % (opt.fxosversion, bug_to_advisory[int(bugid)])
                needs_fixedin += bug_to_advisory[int(bugid)]

            except KeyError:
                info = json.dumps(csv.csv[bugid], sort_keys=True, indent=4)
                print "WARNING: bug %s is marked as having advisory, but doesn't: \n%s" % (bugid, info)
                dangling_bugs.append(bugid)

    print "\n\nAdding 'fixed_in: %s' to advisories..." % opt.fxosversion
    uniq_needs_fixedin = []
    for x in needs_fixedin:
        if x not in uniq_needs_fixedin:
            uniq_needs_fixedin.append(x)
    for needsfix in uniq_needs_fixedin:
        print "Fixing", needsfix
        unfixed = MfsaMd(adv.getAdvisory(needsfix))
        fixed = unfixed.addFixedinToOriginal(opt.fxosversion)
        if not opt.dryrun:
            adv.writeAdvisory(needsfix, fixed)
        else:
            print >>sys.stderr, "WARNING: skipping write to %s" % filename

    print "\n\nHere's your TODO list:\n"
    for dirpath, dirnames, filenames in os.walk("TODO"):
        for f in filenames:
            print "%s/%s" % (dirpath, f)

    print "\nTODO buglist: https://bugzilla.mozilla.org/buglist.cgi?bug_id=%s" % ",".join(needs_advisory)

    print "\nDangling bugs: https://bugzilla.mozilla.org/buglist.cgi?bug_id=%s\n" % ",".join(dangling_bugs)

    if opt.ipython:
        from IPython import embed
        embed()


#############################################################################################################

def printInfoOnEverything(opt):
    adv = MfsaDB()
    print json.dumps(adv.allAdvisoryInfo(), sort_keys=True, indent=4)
    if opt.bugcsv is not None:
        csv = BugzillaSecurityCSV(opt.bugcsv)
        print json.dumps(csv.csv, sort_keys=True, indent=4)
        from IPython import embed
    if opt.ipython:
        from IPython import embed
        embed()


def ipythonShell(opt):
    adv = MfsaDB()
    if opt.bugcsv is not None:
        csv = BugzillaSecurityCSV(opt.bugcsv)
    from IPython import embed
    embed()


#############################################################################################################
# main
########

def main():
    from optparse import OptionParser

    usage = "usage: %prog [options] info|roundup|ipython"
    parser = OptionParser(usage=usage, version="%prog "+version)
    parser.add_option("-b", "--bugs", action="store", dest="bugcsv", default=None,
                      help="Bugzilla CSV export file to parse")
    parser.add_option("-r", "--release", action="store", dest="fxosversion", default=None,
                      help="Firefox OS release version for advisories")
    parser.add_option("--dry-run", dest="dryrun", action="store_true", default=False,
                      help="Do not write out file changes")
    parser.add_option("-i", "--ipython", dest="ipython", action="store_true", default=False,
                      help="drop into ipython session")
    (opt, args) = parser.parse_args()

    if len(args) == 0:
        print >>sys.stderr, "ERROR: no command given"
        sys.exit(5)

    cmd = args[0]

    if cmd == "ipython":
        ipythonShell(opt)

    elif cmd == "dump":
        printInfoOnEverything(opt)

    elif cmd == "roundup":
        if opt.bugcsv is None:
            print >>sys.stderr, "ERROR: 'roundup' requires --bugs argument"
            sys.exit(5)
        if opt.fxosversion is None:
            print >>sys.stderr, "ERROR: 'roundup' requires --release argument"
            sys.exit(5)
        advisoryRoundup(opt)

    else:
        print >>sys.stderr, "ERROR: unknown command '%s'" % cmd


if __name__ == "__main__":
    main()
