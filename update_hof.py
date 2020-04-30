#!/usr/bin/env python3
# -*- coding: utf8 -*-

import requests
import argparse
import pprint
import sys
import re
import hmac
import time
from datetime import datetime
import os
import base64

HEADERS = { 'Accept': 'application/json' }
BASE_URL = 'https://bugzilla.mozilla.org/rest/'
HMAC_KEY_ATTACHMENT_ID = 9133354 # Bug 1622495
search_url = BASE_URL + 'bug' + \
"""
?x=x
&limit=0
&chfield=bug_status
&chfieldfrom=-10y
&f1=classification
&o1=notequals
&v1=Graveyard
&f2=OP
&j2=OR
&j3=OR
&f3=OP
&f4=flagtypes.name
&o4=substring
&v4=sec-bounty-hof%2B
&f5=flagtypes.name
&o5=substring
&v5=sec-bounty%2B
&f6=CP
&f7=OP
&f8=alias
&o8=substring
&v8=CVE-
&f9=flagtypes.name
&o9=substring
&v9=sec-bounty-
&f10=CP
&f11=CP
&classification=Client%20Software
&classification=Developer%20Infrastructure
&classification=Components
&classification=Server%20Software
&classification=Other
&product=Core
&product=External%20Software%20Affecting%20Firefox
&product=Firefox
&product=Firefox%20for%20Android
&product=Firefox%20for%20iOS
&product=Focus
&product=DevTools
&product=MailNews%20Core
&product=NSPR
&product=NSS
&product=Pocket
&product=Thunderbird
&product=Toolkit
&product=Calendar
&product=WebExtensions
""".replace("\n", "")

credit_entries = {
    "028ff665214190ae419f0febbdff465f":"James Grant",
    "047a2ade7fdc3c6d84d5dbea228fe71e":"Julien Maladrie",
    "e88dc79e62596108bef66ec6d6d103fa":"Wladimir Palant",
    "14f41cb4275ed7f671a593138b886e84":"Yasin Soliman",
    "b99b716bfc8db49cb857b8996fdc39f1":"Arthur Edelstein",
    "399471310b07538c814c230e9029b0bb":"Wladimir Palant",
    "7a3d52ef9f515ad5d4aad5868c2e65aa":"Chamal De Silva",
    "8de462f5f2d47748bcd761a45f2f157c":"Nicolas Golubovic",
    "302a4e6aa69950cd60e295d433440bd3":"Gustavo Grieco",
    "2920656b8c8d785f7ccecab735a106a8":"SkyLined",
    "ab37a4ca424a143670adc9093c7086b9":"Scott Bell",
    "ab52f2c4485ec82dcd6b5c36b845e6d5":"James Kitchener",
    "1ad1f39c1e7968ff5cfe318281e0455f":"Tyson Smith",
    "76d59fb088161da3466512c6d304ca2f":"Jordi Chancel",
    "887ba2d86d5c5c29814a38c371854928":"Soroush Dalili",
    "87c66fa50295d7055022c4625c76b208":"Rain",
    "7495547634e174c0e2f49e939d6fe3ee":"Scott Bell",
    "75488be765fd509d904767102b6bb6b7":"Mario Heiderich",
    "7dc3304d4c7f8d13fa0f248f54b07a20":"Kaspar Brand",
    "9d69c86b66ca54565cd98aec6b6baaa3":"Ahmed Elsobky",
    "fa9ffd84a1dd2951bcb0d7f8ebae5c84":"Philip Okhonko",
    "05c9059021985684d94c2631e62b9d12" : "Zhang Hanming from 360 Vulcan team",
    "0a446dcb43d3f9f5da29afb14a40e58f" : "Taegeon Lee",
    "0c7f4b38ad0b504cfc48042e14564cc8" : "Paul Stone",
    "0cdb9b89f615c444f832e56c844e9e75" : "Allyson O'Malley",
    "0eaafbf6f9aabe86a4b040ca50d9191a" : "Shinto K Anto",
    "0f05e10145035903cbb34aac06f3edf6" : "Anonymous",
    "0f14322cc49704ac5551ffe5835abd69" : "Sree Visakh Jain (@sreevisakhjain)",
    "0fc499252d7f74175967ba225e186ed9" : "André Bargull",
    "0fed7c4928e7623eeabf7c040b6bc4a5" : "musicDespiteEverything",
    "1248a90a05c7e3a46b97e6aceeb557ce" : "SkyLined",
    "13215febfe461aae88eda362e7c96cee" : "Eili Masami of Tachibana Lab",
    "164a35fccb05c6bb8a26d881da42bda7" : "Muneaki Nishimura (a.k.a. nishimunea)",
    "192aac4383d85b9acf43554612c6b461" : "Vitaly Nevgen",
    "192e0a963474e27f64bf46f0ddde8268" : "Seb Patane",
    "1a20e0311c4352bb986d6e876d4b6e89" : "Fourteenforty Research Institute Japan",
    "1a99b22b84db560244569dcbe868dcd0" : "Andrew Krasichkov",
    "1ababea19b88a30da141dca3bdf006d4" : "sushi Anton Larsson",
    "1b46bfa367b8cddece232ebfddaccc9d" : "Fabián Cuchietti",
    "1c04ef59bd60189ce09cfca187225e75" : "Mohammed Fayez Ahmed Albanna",
    "1cc583009e744f3a2e63c6ca0ca72c10" : "Dhiraj Mishra",
    "1ced3fc2a9846c0b8a9e99db5416fc29" : "Holger Fuhrmannek",
    "1d239c1ff42a3e8e1c16c976020fd45f" : "Philipp Kewisch",
    "1d6eb1c6e8a177847eca74cad00fc301" : "José María Acuña Morgado",
    "1e304bfde59dcfb0131e21e913281614" : "Luigi Gubello",
    "1e7c9dd1924cf9763c2507c94be341c2" : "Linus Särud",
    "1ffe73fabf298c651b7a8c750de530d2" : "Siraje Amarniss of Fukusa",
    "21c712eaa986e0ae3e135fe689259684" : "Matthew Somerville",
    "2841918025ae79884c3eac763a453b76" : "Jens Gorontzi",
    "2bb8b9860ce62f3fbc9e7eec1a9d5ed0" : "Giorgio Maone of NoScript",
    "2cbc00679c4b47da86d775e2c98d4bd6" : "Zhou Yuyang",
    "31b9334ff2ac135414563035a5c11823" : "Context Information Security",
    "337554f7f0ac9ded2ef6110a7a12910b" : "David Dworken",
    "342df00dfa13da31ecc6efe69d5f6da6" : "moz_bug_r_a4",
    "3597ac4747474360b391a5e359948ca9" : "Mario Gomes",
    "359ee9ee2e4c35e5fa8097e48bd22c50" : "Vladimir Metnew",
    "373ff2b767419c0619f3991348f8d930" : "David Chan",
    "37a2557cee7c4198951b1af8b1243a2e" : "Georg Koppen of The Tor Project",
    "38161e481b381a72de3c4804a292d4ab" : "Atte Kettunen",
    "39897587a528519753812e6f6256f6bd" : "firehack",
    "3a98d1971bc7fab8d457063492a5a467" : "Rafay Baloch of Pakistan Telecommunications Authority ",
    "3c098d6ead472177028bde34acacb5f1" : "Takeshi Terada of Mitsui Bussan Secure Directions Inc.",
    "3f3fae9ad20da4c5655ceda765563e6c" : "Benjamin Kunz Mejri",
    "45e5fe739d4a915a757b37940170e852" : "Harry Gertos",
    "4649493b3babcd55144931b73a973bce" : "Yaniv Frank with SophosLabs",
    "46b96542a8687c90e46400e780b6b4ac" : "Anonymous",
    "47403ba3cf9bcae0874a07f299f643f0" : "Chris Rohlf",
    "49c31aaa040fce3a5fcaf771ad56b382" : "AaylaSecura1138",
    "4a5880b0447f7349c9cbcff76045b3e6" : "Rayyan Bijoora",
    "4a66274c7f1063c7ef3b3c3d9f747566" : "Craig Disselkoen",
    "4b52df50eaaf097f6f062bfea6cf0abe" : "Artur Osiński (Virtual_ManPL)",
    "4b7fd0d6665950db856bc5e22846f719" : "Tobias Klein",
    "4bf2165b96b2506a0ac2212b39fb78b1" : "Clémentine Maurice",
    "4cb38b42bb161ce775b5e7f91d260d3f" : "Daniel Maksimovic",
    "4ea165c7445cfa9a7ed0685e64cdf1fb" : "Paul Stone of Context Information Security",
    "5080064df3a2c21441c9fb6cc3b5f816" : "Jerry Decime",
    "5fbaf4a6794928a04644d7a0a73f7141" : "Alexander Klink",
    "64e04ce43d3007a00b51c63553c48efb" : "p4fg",
    "654445704639346f526d1ef514d08fd7" : "ACROS Security",
    "690334c0cae6df099269d105526a42f3" : "Jordi Chancel",
    "704b002c6bd62215d3738f6fe9c6524a" : "Gregory Smiley of Security Compass",
    "70cc13ce2ba436916140efa887a10fca" : "Falko Strenzke of cryptosource GmbH",
    "71106bd16473852ff8d395e9eb2be45c" : "mlfbrown",
    "723fd46df5eb10ad0fa79da65d7cc961" : "Samuel Erb",
    "740b81a60bd25700b839f63e8d937796" : "Karthik Kumar reddy",
    "755ae0590425c02b3c203036df1a7e1e" : "Tim Hemel",
    "7645f2eb64dccd9602b24b6ce9fce138" : "Chun Han Hsiao",
    "78eeb94fe5fe67f95d9cd574d9ec69db" : "Inko",
    "7aba285c7e4b7f41df3dae6f4becd2a9" : "Sebas (@0xroot)",
    "7b33d07bc038c1ec083e51e31e139fdb" : "Joshua Graham of TSS & Brendan Scarvell",
    "7bd9d5640cb0f0dd5e59ccd7b02a0349" : "Omair",
    "7bed3bd152a0fd4badc6d2ddd4e86e1b" : "Rafael Gieschke",
    "7e1e41ab0cd46a4a32c82def7b840a6d" : "Mario Heiderich of Cure53",
    "7edb6115b239d771b9689857b9e95568" : "Hanno Böck",
    "80e0b8cb2a22f8b9669d2ca1968ce898" : "Eduard Wirch",
    "815f2b92b84655f6a7e9e53ad10e78f4" : "Mitchell Harper",
    "817bd7bdff0d93ccdada8707b5278a08" : "Alexander Nagy",
    "82d7844614f152d6865e83d43f040a8b" : "Antonio Sanso",
    "8314603008777278fd70c0b9b4f01645" : "Adam Barth",
    "8363fd9f9f37fbaf5d600e676bf3aec5" : "Muhammad R. Maulana",
    "87b3f4e2ea33d7e5aea49e26dab8ab5b" : "Jethro Beekman - Security Researcher at University of California - Berkeley",
    "89a138d6477c6a80b7f6c2e59a6c2fa4" : "Anurag Jain",
    "8f3b70144b559447d576b239d48e3b77" : "Max May",
    "8ff363f2185736b3ad47f35f8140c82a" : "Mei Wang of GearTeam Qihoo 360.",
    "9219e61c33ff1e2d14b670b865caffa8" : "Nikhil Mittal",
    "9228cdb27944fb384f1305d2d0c350b8" : "Tushar Rawool",
    "92979b13d84087187a7d5630e1c76b87" : "Luke Li",
    "937c35a7adce7a73254cf0c2ed905e9c" : "Raphael Shaniyazov",
    "95663a4cc4fa467fdd949b16b6e03760" : "knud",
    "9667bad21b75845c367e1c91ea59d788" : "jensvoid",
    "96b79d035cfa51215a941052528e9182" : "Michał Bentkowski",
    "9832ee85d3227243306872874b7157ea" : "Jianjun Chen",
    "9a7ef4ebc1fe8c5e7f59016564db97b4" : "Yossi Oren",
    "9d3bc5f160291389423da6ff52f5bc44" : "Luật Nguyễn",
    "9d729c1661a6d2474eb380131765eb6a" : "Abhishek Arya",
    "9d81009615f1e3b3b269eb78a4abd529" : "David Huang",
    "9de234ea6d5568ef604dd3431af941e4" : "James Lee",
    "9e6d48cc96c5931585cbe2bfc66246b8" : "Aki Helin",
    "a71a35e2a42f69964a986531483ab405" : "Jack Wrenn",
    "a8b84761cdafee6392f64aa115edc48b" : "Andrei Cristian Petcu",
    "a9173d90c2151988a643fee35abafb9f" : "Juho Nurminen",
    "a9e1d36bf363994f9a39353d1e384eab" : "guyio",
    "ab54897026ce6f76bb9cbaf9a86a1fc8" : "Brian 'geeknik' Carpenter",
    "ac6cb3312f13091a2b1ab69bb496057d" : "Rob Wu",
    "ad4e3024178ee23278381ebfbc54528f" : "Looben Yang",
    "b18940ae4a081c594022bcd56e7d949a" : "Ronald Crane",
    "b1a7d637734d5dad9b43136609c8f31f" : "Ronald Crane",
    "b1bce803655916f8687d2da2787a17c6" : "Clément Lavoillotte",
    "b309975ebb9ea77a8021712f1fc0d908" : "Ezra Caltum",
    "b55ff048a2450ef3b41abb9208d836d6" : "Diego Calleja",
    "b5e1a616809a7f78f4b1709fa2cae1ac" : "Steven M Crane",
    "b7b33547a73d2d2c7325f2c47406805f" : "Rakesh Mane",
    "ba257210862ef5ec1080279dd1bec6c4" : "Ken Okuyama",
    "bc1ce7e8b84b814c2eaf2566e4787881" : "Brian Smith",
    "bc9f571d28511fa67d79a20b81d1cd58" : "Kalel",
    "bca639214bd2b582e62763ecc183babd" : "Mike Cardwell",
    "bf39fa273742eda0011a11c8e5369e4b" : "Nicolas Grégoire of AGARRI",
    "c0b9ff5423b4fb9dc26b58576cd4497a" : "Toni Huttunen",
    "c0f5791dfa8c00979d4df44e3f25f884" : "Nicolas Trippar of Zimperium zLabs",
    "c4e343b957ed04e78035e9f1e9b99290" : "Filipe Gomes",
    "c78082d6d5aae54b54f48cecc0f97bed" : "Ms2ger of Igalia",
    "c8828ea7069b5acf239d313675eec592" : "R at Zero Day LLC",
    "ca5c500dbd892f7c06f6a7323220b2b6" : "Scott Zimmermann",
    "cbbcaac86318f769b1f0b9237af85927" : "Yuji Tounai of Mitsui Bussan Secure Directions, Inc.",
    "cc25b3565b0e7f0a2bde8c4e8cecbbd5" : "Nikita Arykov - Security Architect at Pushwoosh Inc.",
    "cc84fd0104bbdf21f5ebfe017f47ba31" : "Quarkslab security engineer Francis Gabriel",
    "cd0b10f0a5f56b3d04ea1a11cd009500" : "Aki Helin",
    "d4c22b801d906fd988e857e28e0d4398" : "team509",
    "d53d5650291b09956d8d8fdc488e1d5b" : "Armin Razmjou",
    "d6baf622b490bffd8c025e615ef460d2" : "crixer",
    "d8edb7c1182dd0cc123dc47dcac28cee" : "Zhanjia Song",
    "d9147aad8edeb19e373570a6cb612b31" : "Rhys Enniks",
    "da370b9a066b1f80464a33801840e392" : "Team sutegoma2 - Japanese CTF team from AVTOKYO",
    "dd54e66b7d54126ca5647d1fd2492353" : "Craig Disselkoen",
    "ddc9459ee44cb5366ad418f992aa47a3" : "Brandon Wieser of Cyber Sensei",
    "de93fee584390b928b2d12bd3d198fc0" : "0days Engineer",
    "dfce8e4c8278c73ffa3ace9344e86572" : "Antoine Delignat-Lavaud",
    "e064c5dd0686bd77a7bb7cc538547d8d" : "Jethro Beekman - Security Researcher at University of California - Berkeley",
    "e0a2ecaef5c7fa9bf90731771aac2e95" : "Marc Schoenefeld",
    "e22e60864c27178d2469566dbcfb4e09" : "Michal Zalewski",
    "e2b442dbd6ddf0e28802b71bb4cf4376" : "Artur Osiński (Virtual_ManPL)",
    "e310574c3c35c503d99ef03885b7ef3a" : "Jay Gilbert",
    "e33752885775e4a274c6db31c995434b" : "Brian Carpenter of Geeknik Labs & Farm",
    "e4e810ec230795b44abbeb37d56b86e8" : "Abdulrahman Alqabandi",
    "e5d2322aa516d90b7eb9a84d7b890938" : "Björn Ruytenberg",
    "e750febf3b1e213b458f017fac835b27" : "Rh0",
    "e751036f55bbf501042162b16c883b4e" : "Nicolas Francois",
    "e7ae95aeff3bef60565d9a3bed3cfe46" : "Frederic Besler @ LAF INTL",
    "e875c787e17ec52abf8d743191dfdb57" : "Jun Kokatsu",
    "e8abc376c3254bcb714b250241b75011" : "insertscript",
    "e8df4fcdfce3352bfa7c8cc4f30cf852" : "Thomas Imbert",
    "ec2382571a4578416a9eef5ec2e8a937" : "Nils",
    "ecbb5f9fa8cdf3d6339da4dc4bd08593" : "Thai \"thaidn\" Duong",
    "f1d319a4f2eaf69d8489a741df1500d8" : "Francisco Alonso",
    "f2c90725c145fe10ebe35533891a1cbc" : "fatal0",
    "f42ea3053e8f3c5af81d1a33cb46e47e" : "Tsubasa Iinuma of Gehirn Inc.",
    "f45fcaee888e8eab311d5d869b48f6e4" : "Zach Hoffman",
    "f46a207798ca14de0287172ce8d47783" : "Linus Särud",
    "f5550452710913283cbf6db0976e2420" : "Konark Modi of Cliqz GmbH",
    "f8266c7296c7f7d996e0040ad7843bf0" : "Robert Kugler",
    "fcf7ed040fa3561f7c7f23784de25ca6" : "R at Zero Day LLC",
    "fe7f319c61c0b44d4cb751afda4f4aeb" : "Gaurav Popalghat",
    "fea05bd1b815660051bf5d090eb4e522" : "Aral Yaman",
    "89ae6542ce619780d318477fe724bb57" : "gfleischer",
    "ea3d4c453e3dcd5b7c3430a9d3b5cecf" : "Jann Horn",
    "76d59fb088161da3466512c6d304ca2f" : "Jordi Chancel",
    "1ad1f39c1e7968ff5cfe318281e0455f" : "Tyson Smith",
    "158f1b632674edbf228a5d98269822af" : "Christian Holler",

}
twitter_entries = {
    "0c7f4b38ad0b504cfc48042e14564cc8" : "@pdjstone",
    "0cdb9b89f615c444f832e56c844e9e75" : "@ally_o_malley",
    "0eaafbf6f9aabe86a4b040ca50d9191a" : "@5hint0",
    "192e0a963474e27f64bf46f0ddde8268" : "@sebbity",
    "1cc583009e744f3a2e63c6ca0ca72c10" : "@RandomDhiraj",
    "1d239c1ff42a3e8e1c16c976020fd45f" : "@pkewisch",
    "3597ac4747474360b391a5e359948ca9" : "@netfuzzer",
    "359ee9ee2e4c35e5fa8097e48bd22c50" : "@vladimir_metnew",
    "38161e481b381a72de3c4804a292d4ab" : "@attekett",
    "3a98d1971bc7fab8d457063492a5a467" : "@rafaybaloch",
    "4bf2165b96b2506a0ac2212b39fb78b1" : "@BloodyTangerine",
    "5080064df3a2c21441c9fb6cc3b5f816" : "@declme",
    "64e04ce43d3007a00b51c63553c48efb" : "@p4fg",
    "815f2b92b84655f6a7e9e53ad10e78f4" : "@HarperMitchell",
    "82d7844614f152d6865e83d43f040a8b" : "@asanso",
    "8363fd9f9f37fbaf5d600e676bf3aec5" : "@agamimaulana",
    "89a138d6477c6a80b7f6c2e59a6c2fa4" : "@csanuragjain",
    "9219e61c33ff1e2d14b670b865caffa8" : "@c0d3G33k",
    "9667bad21b75845c367e1c91ea59d788" : "@jensvoid",
    "9832ee85d3227243306872874b7157ea" : "whucjj",
    "9a7ef4ebc1fe8c5e7f59016564db97b4" : "@yossioren",
    "9d3bc5f160291389423da6ff52f5bc44" : "l4wio",
    "9de234ea6d5568ef604dd3431af941e4" : "@Windowsrcer",
    "a9173d90c2151988a643fee35abafb9f" : "@jupenur",
    "b1bce803655916f8687d2da2787a17c6" : "@clavoillotte",
    "b5e1a616809a7f78f4b1709fa2cae1ac" : "@stevenmcrane ",
    "cbbcaac86318f769b1f0b9237af85927" : "@yousukezan",
    "dd54e66b7d54126ca5647d1fd2492353" : "@craigdissel",
    "e33752885775e4a274c6db31c995434b" : "@geeknik",
    "e4e810ec230795b44abbeb37d56b86e8" : "@qab",
    "e875c787e17ec52abf8d743191dfdb57" : "@shhnjk ",
    "e8abc376c3254bcb714b250241b75011" : "@insertscript",
    "e8df4fcdfce3352bfa7c8cc4f30cf852" : "@masthoon",
    "ecbb5f9fa8cdf3d6339da4dc4bd08593" : "@xorninja",
    "f1d319a4f2eaf69d8489a741df1500d8" : "@revskills",
    "f2c90725c145fe10ebe35533891a1cbc" : "@fatal0_",
    "f42ea3053e8f3c5af81d1a33cb46e47e" : "@llamakko_cafe",
    "f45fcaee888e8eab311d5d869b48f6e4" : "@zrhoffman",
    "f46a207798ca14de0287172ce8d47783" : "@_zulln",
    "f5550452710913283cbf6db0976e2420" : "@konarkmodi",
    "fe7f319c61c0b44d4cb751afda4f4aeb" : "@Gaurav_00000",
}
url_entries = {
    "2920656b8c8d785f7ccecab735a106a8" : "https://skylined.nl",
    "0f14322cc49704ac5551ffe5835abd69" : "https://www.wayanadweb.com",
    "1248a90a05c7e3a46b97e6aceeb557ce" : "https://skylined.nl",
    "192aac4383d85b9acf43554612c6b461" : "https://facebook.com/vitaly.nevgen",
    "1c04ef59bd60189ce09cfca187225e75" : "https://www.linkedin.com/in/mohammedfayez",
    "1d6eb1c6e8a177847eca74cad00fc301" : "https://tecnoblog.guru/",
    "1e304bfde59dcfb0131e21e913281614" : "https://gubello.me",
    "1ffe73fabf298c651b7a8c750de530d2" : "https://fukusa.nl",
    "21c712eaa986e0ae3e135fe689259684" : "http://dracos.co.uk/",
    "2841918025ae79884c3eac763a453b76" : "https://koelner-pc-hilfe.de",
    "2bb8b9860ce62f3fbc9e7eec1a9d5ed0" : "https://maone.net",
    "3c098d6ead472177028bde34acacb5f1" : "http://www.mbsd.jp/",
    "3f3fae9ad20da4c5655ceda765563e6c" : "https://www.vulnerability-lab.com",
    "47403ba3cf9bcae0874a07f299f643f0" : "https://struct.github.io",
    "4a5880b0447f7349c9cbcff76045b3e6" : "https://facebook.com/Bijoora",
    "4b7fd0d6665950db856bc5e22846f719" : "http://www.trapkit.de/",
    "4cb38b42bb161ce775b5e7f91d260d3f" : "https://www.linkedin.com/in/daniel-maksimovic-73537882",
    "654445704639346f526d1ef514d08fd7" : "https://acrossecurity.com/",
    "740b81a60bd25700b839f63e8d937796" : "http://linkedin.com/in/karthik-kumar-reddy-3b10b4128",
    "755ae0590425c02b3c203036df1a7e1e" : "http://www.securesoftware.nl",
    "7aba285c7e4b7f41df3dae6f4becd2a9" : "https://bishopfox.com/",
    "7bd9d5640cb0f0dd5e59ccd7b02a0349" : "https://krashconsulting.com",
    "7e1e41ab0cd46a4a32c82def7b840a6d" : "http://cure53.de/",
    "7edb6115b239d771b9689857b9e95568" : "https://hboeck.de/",
    "80e0b8cb2a22f8b9669d2ca1968ce898" : "https://ewirch.github.io/",
    "817bd7bdff0d93ccdada8707b5278a08" : "https://axen-cyber.com",
    "8314603008777278fd70c0b9b4f01645" : "http://www.adambarth.com/",
    "9228cdb27944fb384f1305d2d0c350b8" : "https://facebook.com/tkrawool",
    "95663a4cc4fa467fdd949b16b6e03760" : "https://labs.f-secure.com/",
    "9d81009615f1e3b3b269eb78a4abd529" : "https://www.linshunghuang.com/",
    "9e6d48cc96c5931585cbe2bfc66246b8" : "https://haltp.org",
    "a71a35e2a42f69964a986531483ab405" : "https://jswrenn.com/",
    "ac6cb3312f13091a2b1ab69bb496057d" : "https://robwu.nl",
    "b1a7d637734d5dad9b43136609c8f31f" : "https://www.zippenhop.com/",
    "b7b33547a73d2d2c7325f2c47406805f" : "https://rakeshmane.com/",
    "bc1ce7e8b84b814c2eaf2566e4787881" : "https://briansmith.org/",
    "bca639214bd2b582e62763ecc183babd" : "https://www.grepular.com/",
    "bf39fa273742eda0011a11c8e5369e4b" : "http://www.agarri.fr/",
    "c78082d6d5aae54b54f48cecc0f97bed" : "https://twitter.com/Ms2ger",
    "ca5c500dbd892f7c06f6a7323220b2b6" : "https://github.com/sczi",
    "d53d5650291b09956d8d8fdc488e1d5b" : "https://rawsec.net/",
    "da370b9a066b1f80464a33801840e392" : "http://ja.avtokyo.org/projects/sutegoma2",
    "ddc9459ee44cb5366ad418f992aa47a3" : "http://www.cybersensei.io",
    "de93fee584390b928b2d12bd3d198fc0" : "http://0days.engineer",
    "dfce8e4c8278c73ffa3ace9344e86572" : "https://antoine.delignat-lavaud.fr",
    "e064c5dd0686bd77a7bb7cc538547d8d" : "https://jbeekman.nl/",
    "e0a2ecaef5c7fa9bf90731771aac2e95" : "https://de.linkedin.com/in/marcschoenefeld",
    "e22e60864c27178d2469566dbcfb4e09" : "http://lcamtuf.coredump.cx/",
    "e5d2322aa516d90b7eb9a84d7b890938" : "https://bjornweb.nl/",
    "f8266c7296c7f7d996e0040ad7843bf0" : "https://www.s3cur3.it/",
}

products = [
    "Core",
    "External Software Affecting Firefox",
    "Firefox",
    "Firefox for Android",
    "Firefox for iOS",
    "Focus",
    "MailNews Core",
    "NSPR",
    "NSS",
    "Pocket",
    "Thunderbird",
    "Toolkit",
    "WebExtensions",
    "DevTools",
    "Calendar",
]

def main():
    args = command_line()

    # Do this first so we error immediately if the file isn't there.
    with open(os.path.abspath(args.output), 'r') as f:
        file_data = f.read()
        f.close()

    hmackey = get_hmac_key(args.apikey)
    debuglog = open('debuglog.' + str(int(time.time())) + '.log', 'w')

    bugs = gather_bug_list(args.apikey)
    hof_entries = []

    (begin_date, end_date) = define_dates(args.quarter, args.year)
    print("Generating Bug Data from " + str(len(bugs["bugs"])) + " bugs")
    num_processed = 0
    for bug in bugs["bugs"]:
        num_processed += 1
        if num_processed % 100 == 0:
            print("Processed", num_processed, "of", len(bugs["bugs"]))
        if bug['product'] not in products:
            continue

        bugid = str(bug["id"])
        debuglog.write(bugid + ",")

        data ={}

        # ==========================================================================================
        # Look for the bug bounty attachment first
        attachment_url = BASE_URL + 'bug/' + bugid + '/attachment'
        try:
            attachments = requests.get(attachment_url, headers=HEADERS, params={'api_key' : args.apikey}).json()['bugs'][bugid]
        except json.decoder.JSONDecodeError as e:
            # Try this a couple times, it'll probably work eventually.
            try:
                attachments = requests.get(attachment_url, headers=HEADERS, params={'api_key' : args.apikey}).json()['bugs'][bugid]
            except json.decoder.JSONDecodeError as e:
                attachments = requests.get(attachment_url, headers=HEADERS, params={'api_key' : args.apikey}).json()['bugs'][bugid]
        except requests.exceptions.RequestException as e:
            print ("Error in " + bugid)
            print (e)
            continue

        # attachment_breakout[0] = email
        # attachment_breakout[1] = paid
        # attachment_breakout[2] = reported date
        # attachment_breakout[3] = fixed date
        # attachment_breakout[4] = awareded date
        # attachment_breakout[5] = publish (true/false)
        # attachment_breakout[6] = credit
        # attachment_breakout[7] = twitter
        # attachment_breakout[8] = url
        
        foundAttachment = None
        for attachment in attachments:
            if attachment['file_name'] == 'bugbounty.data' and attachment['is_private'] == 1:
                if foundAttachment:
                    raise Exception("Two bug bounty attachments were found for " + bugid)
                foundAttachment = attachment

        if foundAttachment:
            try:
                attachment = foundAttachment

                data = {}
                attachment_breakout = attachment['description'].split(',')
                data["email"] = attachment_breakout[0]
                data["email_hmac"] = hmac_email(hmackey, attachment_breakout[0])
                data["date_raw"] = attachment_breakout[4] or attachment_breakout[3] or attachment_breakout[2]
                data["date"] = datetime.strptime(data["date_raw"], '%Y-%m-%d')
                
                debuglog.write(data["date_raw"] + "," + data["email"] + "," + data["email_hmac"] + ",")
                
                if begin_date < data["date"] < end_date:
                    if "@mozilla.com" in data["email"] and mozilla_email_was_employed(data["email"], data["date"]):
                        debuglog.write("Mozilla Employee in a Bug Bounty Attachment??\n")
                        # Don't add Mozilla employees filing bugs under their work email to the HOF
                        continue

                    # print("Generating Data For Bug %s - %s" % (bugid, data["email"]))
                    numFields = len(attachment_breakout)

                    if not bool(attachment_breakout[5]) or "no" == attachment_breakout[5].lower():
                        debuglog.write("Do Not Publish\n")
                        # Do not publish
                        continue

                    data["name"] = ""
                    if numFields > 6 and attachment_breakout[6]:
                        data["name"] = attachment_breakout[6]

                        if "[paid]" in data["name"]:
                            data["name"] = ""
                        elif "no response" in data["name"]:
                            data["name"] = ""
                        elif data["name"][0] == '"' and data["name"][-1] == '"':
                            data["name"] = data["name"][1:-1]
                    
                        if data["name"] and data["email_hmac"] not in credit_entries and \
                           check_add_credit_to_script(data["email"], data["name"]):
                            add_credit_to_script(hmackey, data["email"], data["name"])

                    if not data["name"] and data["email_hmac"] in credit_entries:
                        data["name"] = credit_entries[data["email_hmac"]]
                    elif not data["name"]:
                        user_url = BASE_URL + 'user?names=' + data["email"]
                        try:
                            user_response = requests.get(user_url, headers=HEADERS)
                            user_response_data = user_response.json()
                        except requests.exceptions.RequestException as e:
                            print("Could not get user data for " + user_url)
                            print(e)
                            sys.exit(1)

                        if user_response.status_code == 200 and user_response_data['users'][0]["real_name"]:
                            data["name"] = user_response_data['users'][0]["real_name"]
                        else:
                            data["name"] = data["email"].split('@', 1)[0]
                            print("Had to use fallback name for", bugid, data["email"], data["name"])
                    
                    data["quarter-string"] = data["date_raw"][0:4] + month_to_quarter(data["date_raw"][5:7])

                    if data["email_hmac"] in twitter_entries:
                        data["twitter"] = twitter_entries[data["email_hmac"]]
                    elif numFields > 7 and attachment_breakout[7]:
                        data["twitter"] = attachment_breakout[7]
                        add_twitter_to_script(hmackey, data["email"], data["twitter"])

                    if data["email_hmac"] in url_entries:
                        data["url"] = url_entries[data["email_hmac"]]
                    elif numFields > 8 and attachment_breakout[8]:
                        data["url"] = attachment_breakout[8]
                        add_url_to_script(hmackey, data["email"], data["url"])
                    
                    if not "url" in data and "twitter" in data:
                        data["url"] = "https://twitter.com/" + data["twitter"]

                    hof_entries.append(data)
                    debuglog.write(data["name"] + "," + (data["url"] if 'url' in data else "") + "\n")
                    continue # Go to next bug
                else:
                    debuglog.write("Date wasn't in range\n")
                    continue
            except:
                debuglog.write("Printed Exception\n")
                import traceback
                print("--------------------------------------------------------")
                print("Could not process %s" % bugid)
                print("Attachment field: %s" % attachment['description'])
                print("Split fields: %s" % attachment['description'].split(','))
                print(traceback.format_exc())
                print("--------------------------------------------------------")
                continue

        # ==========================================================================================
        # If we didn't find a bounty attachment, then it's a Hall of Fame Entry
        if 'cf_last_resolved' not in bug or not bug['cf_last_resolved']:
            # Unusual case
            data["date_raw"] = bug['creation_time'].split("T")[0]
        else:
            # Normal case
            data["date_raw"] = bug['cf_last_resolved'].split("T")[0]
        data["date"] = datetime.strptime(data["date_raw"], '%Y-%m-%d')
        debuglog.write(data["date_raw"] + ",")

        if begin_date < data["date"] < end_date:
            data["name"] = ""
            data["email"] = bug['creator_detail']['email']
            data["email_hmac"] = hmac_email(hmackey, data["email"])
            debuglog.write(data["email"] + "," + data["email_hmac"] + ",")

            if "@mozilla.com" in data["email"] and mozilla_email_was_employed(data["email"], data["date"]):
                debuglog.write("Mozilla Employee??\n")
                # Don't add Mozilla employees filing bugs under their work email to the HOF
                continue
            
            # print("Generating Data For Bug %s - %s" % (bugid, data["email"]))
            if data["email_hmac"] in credit_entries:
                data["name"] = credit_entries[data["email_hmac"]]
            else:
                user_url = BASE_URL + 'user?names=' + data["email"]
                try:
                    user_response = requests.get(user_url, headers=HEADERS)
                    user_response_data = user_response.json()
                except requests.exceptions.RequestException as e:
                    print("Could not get user data for " + user_url)
                    print(e)
                    sys.exit(1)

                if user_response.status_code == 200 and user_response_data['users'][0]["real_name"]:
                    data["name"] = user_response_data['users'][0]["real_name"]
                else:
                    data["name"] = data["email"].split('@', 1)[0]
                    print("Had to use fallback name:", bugid, data["email"], data["name"])

            data["quarter-string"] = data["date_raw"][0:4] + month_to_quarter(data["date_raw"][5:7])

            if data["email_hmac"] in twitter_entries:
                data["twitter"] = twitter_entries[data["email_hmac"]]

            if data["email_hmac"] in url_entries:
                data["url"] = url_entries[data["email_hmac"]]
            
            if not "url" in data and "twitter" in data:
                data["url"] = "https://twitter.com/" + data["twitter"]

            hof_entries.append(data)
            debuglog.write(data["name"] + "," + (data["url"] if 'url' in data else "") + "\n")
            continue # Go to next bug (although we're already at the end of the loop.)
        else:
            debuglog.write("Date wasn't in range\n")
            continue


                    
    def soryByDate(val):
        return val["date"]

    hof_entries.sort(key=soryByDate, reverse=True)

    oneEntryPerQuarter = set()

    hof_output = ""
    for data in hof_entries:
        try:
            thisData = data["name"] + " " + data["quarter-string"]
            if thisData in oneEntryPerQuarter:
                continue

            oneEntryPerQuarter.add(thisData)
            hof_output = hof_output + "- name: {}\n".format(data["name"])
            hof_output = hof_output + "  date: {}\n".format(data["date_raw"])

            if "twitter" in data:
                hof_output = hof_output + "  twitter: {}\n".format(data["twitter"])
            if "url" in data:
                hof_output = hof_output + "  url: {}\n".format(data["url"])
        except:
            print("Could not write hof entry for ", data["name"])

    final_output = file_data[:6] +'\n' + hof_output.rstrip() + file_data[6:]

    with open(os.path.abspath(args.output), 'w') as output_file:
        output_file.write(final_output)

def define_dates(quarter, year):
    if quarter == "doitall":
        begin_date = datetime.strptime("{}-01-01" .format(2000), '%Y-%m-%d')
        end_date = datetime.strptime("{}-12-31" .format(2019), '%Y-%m-%d')
    elif int(quarter) == 1:
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

def month_to_quarter(month):
    if int(month) <= 3:
        return str(1)
    elif int(month) <= 6:
        return str(2)
    elif int(month) <= 9:
        return str(3)
    else:
        return str(4)


def command_line():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--apikey", help="Bugzila API key",)
    parser.add_argument("-f", "--output", help="YAML file",)
    parser.add_argument("-y", "--year", help="year",)
    parser.add_argument("-q", "--quarter", help="quarter as digit")
    parser.add_argument("--sort-credit-entries", help="Do not update Hall of Fame, just sort the credit entries and output them", action='store_true')
    parser.add_argument("--hmac", help="hmac an email address")
    args = parser.parse_args()

    if args.sort_credit_entries:
        print("credit_entries = {")
        for k in sorted(credit_entries):
            print("    \"" + k + "\" : \"" + credit_entries[k].replace("\"", "\\\"") + "\",")
        print("}")

        print("twitter_entries = {")
        for k in sorted(twitter_entries):
            print("    \"" + k + "\" : \"" + twitter_entries[k].replace("\"", "\\\"") + "\",")
        print("}")

        print("url_entries = {")
        for k in sorted(url_entries):
            print("    \"" + k + "\" : \"" + url_entries[k].replace("\"", "\\\"") + "\",")
        print("}")
        sys.exit(0)
    elif args.hmac and args.apikey:
        print(hmac_email(get_hmac_key(args.apikey), args.hmac))
        sys.exit(0)
    elif args.hmac:
        print("If you request hmac you must also supply --apikey")
        sys.exit(1)
    else:
        if not args.apikey or not args.output or not args.year or not args.quarter:
            parser.print_help()
            sys.exit(1)

    return args

def check_add_credit_to_script(email, credit):
    if " and " in credit:
        # Do not by default, add double-credits as a mapping.
        return False
    if email == "replace@replace.com":
        # This was an old field used to indicate we were filing a bug for someone
        return False
    if "@mozilla.com" in email:
        # Do not add mozilla emails to script, we probably filed them for someone else.
        return False
    if credit.strip()[0] == "@":
        raise Exception("It looks like a Twitter handle is in the credit field.")
    return True

def mozilla_email_was_employed(email, date):
    pre_employment_data = {
        'jdemooij@mozilla.com' : datetime(year=2011, month=11, day=1),
        'choller@mozilla.com' : datetime(year=2011, month=8, day=1)
    }
    if email not in pre_employment_data:
        return True
    return date > pre_employment_data[email]

def hmac_email(hmackey, email):
    return hmac.new(hmackey, email.strip().lower().encode()).hexdigest()

def add_credit_to_script(hmackey, email, credit):
    string_to_add = '"' + hmac_email(hmackey, email) + '":"' + credit + '",'
    with open(os.path.basename(__file__), 'r', encoding="utf-8") as in_script:
        script_data = in_script.read()

    index = script_data.find('credit_entries = {') + 18

    final_output = script_data[:index] +'\n' + "    " + string_to_add + script_data[index:]

    with open(os.path.basename(__file__), 'w', encoding="utf-8") as out_script:
        out_script.write(final_output)

def add_twitter_to_script(hmackey, email, twitter):
    string_to_add = '"' + hmac_email(hmackey, email) + '":"' + twitter + '",'
    with open(os.path.basename(__file__), 'r', encoding="utf-8") as in_script:
        script_data = in_script.read()

    index = script_data.find('twitter_entries = {') + 19

    final_output = script_data[:index] +'\n' + "    " + string_to_add + script_data[index:]

    with open(os.path.basename(__file__), 'w', encoding="utf-8") as out_script:
        out_script.write(final_output)

def add_url_to_script(hmackey, email, url):
    string_to_add = '"' + hmac_email(hmackey, email) + '":"' + url + '",'
    with open(os.path.basename(__file__), 'r', encoding="utf-8") as in_script:
        script_data = in_script.read()

    index = script_data.find('url_entries = {') + 15

    final_output = script_data[:index] +'\n' + "    " + string_to_add + script_data[index:]

    with open(os.path.basename(__file__), 'w', encoding="utf-8") as out_script:
        out_script.write(final_output)

def gather_bug_list(apikey):
    try:
        bugs = requests.get(search_url, headers=HEADERS, params={'api_key':apikey, 'include_fields': 'id, product, cf_last_resolved, creator, creation_time'}).json()
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(1)
    return bugs

def get_hmac_key(apikey):
    key = ""
    try:
        response = requests.get("https://bugzilla.mozilla.org/rest/bug/attachment/" + str(HMAC_KEY_ATTACHMENT_ID), headers=HEADERS, params={'api_key':apikey}).json()
        return base64.b64decode(response['attachments'][str(HMAC_KEY_ATTACHMENT_ID)]['data'])
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(1)
    return key

if __name__ == '__main__':
    main()
