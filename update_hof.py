import requests
import argparse
import pprint
import sys
import re
from datetime import datetime
import collections
import os

HEADERS = { 'Accept': 'application/json' }
BASE_URL = 'https://bugzilla.mozilla.org/rest/'
search_url = BASE_URL + 'bug' + '?quicksearch=ALL%20flag%3Asec-bounty%2b&list_id=12789124&limit=0'
hof_entries = {}

credit_entries = {
    "Griffin@dot.net":"Griffin Francis",
    "Laraweron@gmail.com":"Raphael Shaniyazov",
    "Rh01@protonmail.com":"Rh0",
    "Tazuwk@gmail.com":"Muhammed Gamal Fahmy",
    "a@bugzilla.mozilla.org.m.xn--e-fga5k.de":"Alexander Klink",
    "abbaolk@gmail.com":"Anonymous",
    "adel.afsharipour@gmail.com":"Adel Afsharipour",
    "aditya@manifestsecurity.com":"Aditya Agrawal",
    "admin@sinfocol.org":"Daniel Correa",
    "aki.helin@iki.fi":"Aki Helin",
    "albinowax@eml.cc":"James Kettle",
    "alex.chapman@contextis.co.uk":"Context Information Security",
    "alfredgotu@gmail.com":"Hamza Bettache",
    "andrebargull@googlemail.com":"André Bargull",
    "antoine@delignat-lavaud.fr":"INRIA",
    "aral.yaman@gmx.ch":"Aral Yaman",
    "armin@rawsec.net":"Armin Razmdjou",
    "artur_czyz@wp.pl":"Artur Czyż",
    "attacker911india@gmail.com":"Ankita-Dhakar",
    "attekett@gmail.com":"Atte Kettunen",
    "b@ubeeri.com":"Barrett Adams",
    "bernesb@gmail.com":"Artur Osiński (Virtual_ManPL)",
    "blackfan@ya.ru":"Sergey Bobrov",
    "bogdan.calin@gmail.com":"Bogdan Calin",
    "bogus@bogus.jp":"Yuji Tounai of NTT Communications",
    "brian.carpenter@gmail.com":"Brian geeknik' Carpenter",
    "buglloc@yandex.ru":"Andrew Krasichkov",
    "bugzilla@pdjs.co.uk":"Paul Stone",
    "carlos.mcevilly@gmail.com":"Carlos McEvilly",
    "chhsiao90@gmail.com":"Chun Han Hsiao",
    "cocking70@googlemail.com":"Daniel Cocking",
    "contact@alisa.sh":"Root Object",
    "danutzu7@gmail.com":"Daniel Tomescu",
    "david@daviddworken.com":"David Dworken",
    "david@dchanm.com":"David Chan",
    "decime@gmail.com":"Jerry Decime",
    "e@c.com.mx":"Ezra Caltum",
    "fabiancuchietti@hotmail.com":"Fabián Cuchietti",
    "fcuchietti@gmail.com":"Fabián Cuchietti",
    "fgabriel@quarkslab.com":"Quarkslab security engineer Francis Gabriel",
    "filipesw@gmail.com":"Filipe Gomes",
    "firealwaysworks@gmail.com":"Michael Brooks",
    "firehack0r@gmail.com":"firehack",
    "fstrenzke@cryptosource.de":"Falko Strenzke of cryptosource GmbH",
    "garming@catalyst.net.nz":"Garming Sam (Catalyst IT)",
    "gk@torproject.org":"Georg Koppen",
    "gnehsoah@gmail.com":"Haosheng Wang",
    "gninrepoli@gmail.com":"Aliaksei Panamarenka",
    "gopiengg@gmail.com":"கோபிநாத்(Gopinath) - Madurai",
    "griffin.francis.1993@gmail.com":"Griffin Francis",
    "hanno@hboeck.de":"Hanno Boeck",
    "hassham.nagori95@gmail.com":"Muhammad Hassham Nagori",
    "hofusec@posteo.de":"Holger Fuhrmannek",
    "ignatio2007@gmail.com":"Sergey",
    "illsecresearchgroup@gmail.com":"illSecure Research Group",
    "inferno@chromium.org":"Abhishek Arya",
    "infosecurity@ya.ru":"Oleg Boytsev",
    "ingopan@gmail.com":"Ingo Pan",
    "inko@mailbox.org":"Inko",
    "japp@0xlabs.com":"Jose Antonio Perez",
    "jason@tyrannical.org":"Jason Hamilton",
    "jaumlucas@gmail.com":"Joao Lucas",
    "jay.gilbert.nhs@gmail.com":"Jay Gilbert",
    "jerri.rice.001@gmail.com":"Anonymous",
    "jm.acuna73@gmail.com":"José María Acuña Morgado",
    "johndoe1492@yandex.ru":"Vladimir Polyakov",
    "jordi.chancel@alternativ-testing.fr":"Jordi Chancel",
    "jose_carlos@bsdmail.com":"Jose Carlos Exposito Bueno",
    "kaze.tesla@yahoo.com":"Takashi Suzuki",
    "kenken0980@gmail.com":"Ken Okuyama",
    "kenney_lu@trendmicro.com":"Kenney Lu",
    "kokanin@gmail.com":"Knud",
    "krysztofiak.jedrzej@gmail.com":"Jędrzej Krysztofiak",
    "l33terally@gmail.com":"Shahar Albeck",
    "laf.intel@gmail.com":"Frederic Besler @ LAF INTL",
    "lcamtuf@coredump.cx":"Michal Zalewski",
    "localhostvaibs@gmail.com":"Cody Ward",
    "loobenyang@gmail.com":"Looben Yang",
    "lukezli@yahoo.com":"Luke Li",
    "martinzhou96@outlook.com":"Zhou Yuyang",
    "me@ushi.se":"sushi Anton Larsson",
    "meeposf123@gmail.com":"Waseem Ullah Siddiqui",
    "miaouuuux@gmail.com":"Nicolas Francois",
    "michal@bentkowski.info":"Michał Bentkowski",
    "mohamed.chamli@esprit.tn":"Mohamed Chamli",
    "moz_bug_r_a4@yahoo.com":"moz_bug_r_a4",
    "mrgrek1@gmail.com":"Vladimir Ivanov",
    "netfuzzerr@gmail.com":"Mario Gomes",
    "nikhil.srivastava@techdefence.com":"Advance Techdefence Pvt. Ltd.",
    "nikita.arykov@gmail.com":"Nikita Arykov - Security Architect at Pushwoosh Inc.",
    "nils@vulndev.org":"Nils",
    "ntrippar@gmail.com":"Nicolas Trippar of Zimperium zLabs",
    "oc3f.dz@gmail.com":"Tadj Youssouf",
    "omair@krash.in":"Omair",
    "p4r3sh.p4rm4r@gmail.com":"Paresh",
    "persona@jbeekman.nl":"Jethro Beekman - Security Researcher at University of California - Berkeley",
    "ptheriault@mozilla.com":"James Grant",
    "q1@lastland.net":"Ron Crane",
    "qab@ksu.edu":"Abdulrahman Alqabandi",
    "rafael@gieschke.de":"Rafael Gieschke",
    "rayyanh12@gmail.com":"Rayyan Bijoora",
    "rhys.enniks@gmail.com":"Rhys Enniks",
    "robin7907@hotmail.com":"Robin Puri (Deep Inder Singh Puri)",
    "ronen.zilberman@gmail.com":"Ronen Zilberman",
    "rs@revskills.cz":"Francisco Alonso of NowSecure Research Team",
    "ryandewhurst@gmail.com":"WPScan Team",
    "s.h.h.n.j.k@gmail.com":"Jun Kokatsu",
    "samrerb@erbbysam.com":"Samuel Erb",
    "sdna.muneaki.nishimura@gmail.com":"Muneaki Nishimura (a.k.a. nishimunea)",
    "seb@outofctrl.it":"Sebastian feink0st' Nickel",
    "sebbity@gmail.com":"Seb Petane",
    "secreport@ysx-contact.com":"Yasin Soliman",
    "shinto143@gmail.com":"Shinto K Anto",
    "simonjohnathan@gmail.com":"Johnathan S. Simon (johnathansimon.com)",
    "suzuki@fourteenforty.jp":"Fourteenforty Research Institute",
    "tachibana.laboratory@gmail.com":"Eili Masami of Tachibana Lab",
    "tk.mozilla@gmail.com":"Tobias Klein",
    "todayisnew@gmail.com":"musicDespiteEverything",
    "tom.prince@ualberta.net":"Tom Prince",
    "toni.huttunen@bittikaista.net":"Toni Huttunen",
    "trev.moz@adblockplus.org":"Wladimir Palant",
    "tyhawk9@sbcglobal.net":"Tyler Hawkins",
    "valievkarim@gmail.com":"Karim Valiev",
    "wangmei.S102@gmail.com":"Mei Wang of GearTeam Qihoo 360",
    "websec02.g02@gmail.com":"Takeshi Terada of Mitsui Bussan Secure Directions Inc.",
    "wooshi@gmail.com":"team509",
    "yaaboukir@gmail.com":"Yassine AB",
    "z0jncr4lq@ctrlc.hu":"Stefan Marsiske",
     "zhanghanming@360.cn":"Zhang Hanming from 360 Vulcan team"
}

twitter_entries = {
}

url_entries = {
}

products = [
    "Core",
    "Core Graveyard",
    "External Software Affecting Firefox",
    "Firefox",
    "Firefox for Android",
    "Firefox for Android Graveyard",
    "Firefox for iOS",
    "Focus-iOS",
    "Hello (Loop)",
    "MailNews Core",
    "NSPR",
    "NSS",
    "Pocket",
    "Thunderbird",
    "Toolkit"
]

def main():
    args = command_line()
    bugs = gather_bug_list(args.apikey)
    data ={}

    (begin_date, end_date) = define_dates(args.quarter, args.year)
    print("Generating Bug Data")
    for bug in bugs["bugs"]:
        bugid = str(bug["id"])
        reporter_name = ''

        attachment_url = BASE_URL + 'bug/' + bugid + '/attachment'
        try:
            attachments = requests.get(attachment_url, headers=HEADERS, params={'api_key' : args.apikey}).json()['bugs'][bugid]
        except requests.exceptions.RequestException as e:
            print (e)
            sys.exit(1)

        # attachment_breakout[0] = email
        # attachment_breakout[1] = paid
        # attachment_breakout[2] = reported date
        # attachment_breakout[3] = fixed date
        # attachment_breakout[4] = awareded date
        # attachment_breakout[5] = publish (true/false)
        # attachment_breakout[6] = credit
        # attachment_breakout[7] = twitter
        # attachment_breakout[8] = url
        
        for attachment in attachments:

            if attachment['file_name'] == 'bugbounty.data' and attachment['is_private'] == 1:
                attachment_breakout = attachment['description'].split(',')
                award_date = datetime.strptime(attachment_breakout[4], '%Y-%m-%d')

                if begin_date < award_date < end_date:
                    if bug['product'] in products:
                        print("Generating Data For %s" % attachment_breakout[0]) 
                        user_url = BASE_URL + 'user?names=' + attachment_breakout[0]
                        try:
                            user_response = requests.get(user_url, headers=HEADERS)
                        except requests.exceptions.RequestException as e:
                            print(e)
                            sys.exit(1)
                        if  attachment_breakout[6]:
                            reporter_name = attachment_breakout[6]
                            if attachment_breakout[0] not in credit_entries:
                                add_credit_to_script(attachment_breakout[0], reporter_name)
                        elif attachment_breakout[0] in credit_entries:
                            reporter_name = credit_entries[attachment_breakout[0]]
                        elif user_response.status_code == 200 and user_response.json()['users'][0]["real_name"]:
                                reporter_name = user_response.json()['users'][0]["real_name"]
                        else:
                            reporter_name = attachment_breakout[0].split('@', 1)[0]
                        
                        if reporter_name not in hof_entries:
                            data["date"] = attachment_breakout[4]
                            hof_entries[reporter_name] = data

                        if attachment_breakout[0] in twitter_entries:
                            data["twitter"] = twitter_entries[attachment_breakout[0]]
                        elif attachment_breakout[7]:
                            data["twitter"] = attachment_breakout[7]
                            add_twitter_to_script(attachment_breakout[0], data["twitter"])

                        if attachment_breakout[0] in url_entries:
                            data["url"] = url_entries[attachment_breakout[0]]
                        elif attachment_breakout[8]:
                            data["url"] = attachment_breakout[8]
                            add_url_to_script(attachment_breakout[0], data["url"])
                        
                        if attachment_breakout[8]:
                            data["url"] = attachment_breakout[8]
                    
    ordered_entries = collections.OrderedDict(sorted(hof_entries.items()))

    with open(os.path.abspath(args.output), 'r') as f:
        file_data = f.read()
        f.close()

    hof_output = ""
    for name, data in ordered_entries.items():
        hof_output = hof_output + "- name: {}\n".format(name)
        hof_output = hof_output + "  date: {}\n".format(data["date"])
        if "twitter" in data:
            hof_output = hof_output + "  twitter: {}\n".format(data["twitter"])
        if "url" in data:
            hof_output = hof_output + "  url: {}\n".format(data["url"])

    final_output = file_data[:6] +'\n' + hof_output.rstrip() + file_data[6:]

    with open(os.path.abspath(args.output), 'w') as output_file:
        output_file.write(final_output)

def define_dates(quarter, year):
    if int(quarter) == 1:
        begin_date = datetime.strptime("{}-01-01" .format(year), '%Y-%m-%d')
        end_date = datetime.strptime("{}-03-31" .format(year), '%Y-%m-%d')
    elif int(quarter) == 2:
        begin_date = datetime.strptime("{}-04-01" .format(year), '%Y-%m-%d')
        end_date = datetime.strptime("{}-06-30" .format(year), '%Y-%m-%d')
    elif int(quarter) == 3:
        begin_date = datetime.strptime("{}-07-01" .format(year), '%Y-%m-%d')
        end_date = datetime.strptime("{}-09-30" .format(year), '%Y-%m-%d')
    elif int(quarter) == 4:
        begin_date = datetime.strptime("{}-10-01" .format(year), '%Y-%m-%d')
        end_date = datetime.strptime("{}-12-31" .format(year), '%Y-%m-%d')
    else:
        print("not a valid quarter")
        exit(1)
    return(begin_date, end_date)

def command_line():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--apikey", help="Bugzila API key")
    parser.add_argument("-d","--debug", help="enables debug", action="store_true")
    parser.add_argument("-f", "--output", help="YAML file")
    parser.add_argument("-y", "--year", help="year")
    parser.add_argument("-q", "--quarter", help="quarter as digit")
    args = parser.parse_args()
    return args

def add_credit_to_script(email, credit):
    string_to_add = email + ":" + credit
    with open(os.path.basename(__file__), 'r', encoding="utf-8") as in_script:
        script_data = in_script.read()

    index = script_data.find('credit_entries = {') + 18

    final_output = script_data[:index] +'\n' + "    " + string_to_add + script_data[index:]

    with open(os.path.basename(__file__), 'w', encoding="utf-8") as out_script:
        out_script.write(final_output)

def add_twitter_to_script(email, twitter):
    string_to_add = email + ":" + twitter
    with open(os.path.basename(__file__), 'r', encoding="utf-8") as in_script:
        script_data = in_script.read()

    index = script_data.find('twitter_entries = {') + 19

    final_output = script_data[:index] +'\n' + "    " + string_to_add + script_data[index:]

    with open(os.path.basename(__file__), 'w', encoding="utf-8") as out_script:
        out_script.write(final_output)

def add_url_to_script(email, url):
    string_to_add = email + ":" + url
    with open(os.path.basename(__file__), 'r', encoding="utf-8") as in_script:
        script_data = in_script.read()

    index = script_data.find('url_entries = {') + 15

    final_output = script_data[:index] +'\n' + "    " + string_to_add + script_data[index:]

    with open(os.path.basename(__file__), 'w', encoding="utf-8") as out_script:
        out_script.write(final_output)

def gather_bug_list(apikey):
    try:
        bugs = requests.get(search_url, headers=HEADERS, params={'api_key':apikey, 'include_fields': 'id, product'}).json()
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(1)
    return bugs

if __name__ == '__main__':
    main()
