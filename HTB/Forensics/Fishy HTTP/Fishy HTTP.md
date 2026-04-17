Link: https://app.hackthebox.com/challenges/Fishy%2520HTTP?tab=play_challenge
#Fishy HTTP

## Author: pakcyberbot
### Dfficulty: Easy
## Description: 
I found a suspicious program on my computer making HTTP requests to a web server. Please review the provided traffic capture and executable file for analysis. (Note: Flag has two parts)

### Tools used:
- Kali Linux VM (Oracle Virtual Box)
- Wireshark
- Cyberchef
- Python3
- JetBrains DotPeek

## Solution:
We are given two files: sustraffic.pcapng and smphost.exe. Firstly I analyzed the traffic capture. There were some HTTP traffic with weird content. There were two types of it: html code and text. Examples are below.
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTML Web Server</title>
</head>
<body><button>kangaroo kettle horn</button>
<a href="#">watermelon egg snake nose instrument urn xerophyte yogurt</a>
<button>gift underground pencil eraser pizza yolk mask koala ladder</button>
<span>knight fire leaf jewel popcorn tambourine necklace xylulose</span>
<button>whale underground hedgehog wing fruit bottle honey pencil</button>
<a href="#">urn windmill snake tambourine</a>
<button>umbrella zebra</button>
<img src=quartz ocean>
<ol><li>king tooth house key necklace dolphin xerophyte escalator</li></ol>
<ul><li>ring fruit camera jump cookie table basket nail universe</li></ul>
<ol><li>ink sun ladybug beach hat urn kitchen</li></ol>
<b>clown whale kettle lion jungle king</b>
<ol><li>diamond garden penguin quill quail zigzag apple</li></ol>
<span>invitation ocean uniform volcano</span>
<ol><li>vacuum drum bottle flower</li></ol>
<i>fire turtle squirrel</i>
<ol><li>kettle house horn panda hedgehog xerosis tree astronaut</li></ol>
<ol><li>instrument bird</li></ol>
<ol><li>anchor yew jacket invitation quilt</li></ol>
<blockquote>log easel</blockquote>
</body>
</html>
```

```
feedback: Invitation Fence Zombie vest book Horn Vegetable table Zipper Sun Bottle pencil butterfly igloo Butterfly knight cloud moon log 2 Zebra Squirrel Basket Drum Iguana Ghost hat house cat yolk Ball universe beach yacht Bottle star Yellow Wing Jewel ladybug ball Car 4 Necklace Castle instrument Ball Windmill basket 2 xanthan 1 bicycle Wing Urn guitar Unicorn 2 Vacuum yolk astronaut Watermelon Flag snowman Igloo Escalator 5 1 ball Worm Jar laptop candle island Basket penguin cloud yogurt Butterfly Bicycle Magnet Drum candle 5 Ladybug Utensil Fish Engine Raccoon key Iron Ninja Computer goat 0 Key Island Elephant Radio pear cat magnet Vase jet dragon Garden 9 yodel eraser Snowman Basket van Zebra island Basket Drum Owl lamp xylophone Upholsterer Zebra Whale 1 whale Dolphin Queen orange Nest Cat jet Ant 1 Log zone Apple 3 Lighthouse zelda Ice windmill Mountain jacket Quartz grape Ink Doll Astronaut 5 Olive jack-o-lantern Iron yellow Instrument Elf Fence Net Ice Clown Ant game Invitation Dolphin xerophyte Engine Snake Vest Ice + Igloo Candle Alarm gem Ink Candle Ant gift Ice-cream Castle Album gem Iguana Cat 4 Nail Candle jump Airplane 1 Lock zone Acrobat 3 Laptop zigzag Instrument watch Monkey jacket Quartz glasses Iron Duck Airplane 5 Oyster jet Iron yak Ice Eraser Flower Newspaper Ice-cream Camera Airplane globe Ink Dragon xmas Elephant Sandwich Vacuum Iron + Ink Castle Apple goat Igloo Cake Apple guitar Insect Camera Apple garden Igloo Clown 4 universe Dolphin Quill oven worm Newspaper Squirrel 8 windmill Nail yacht 8 yacht Mouse Dinosaur Iguana 0 Igloo Castle Anchor windmill Nest zap ornament yodel Mushroom yodel Basket Ball Turtle Sock Anchor globe Ink Castle Anchor goat Iron Cake Alarm guitar Notebook juice clown sock Ninja Table Egg 1 Lighthouse Duck computer 0 Ninja Camera Banana zoo bear Xanthan Beach oyster bear 3 Nail 0 Laptop mountain Vegetable 4 Zen Quarterback 0 Koala Ice Cat Acrobat game Insect Cat Apple gift Igloo Clown Alarm gift Iron Cookie Acrobat gem Instrument Camera Astronaut guitar Mountain Ship Beach Globe album Wand x-ray lamp Kangaroo House Mailbox penguin Invitation Castle Ant grape Igloo Cat Ant 2 Ninja yawn whale 1 Microphone Table Unicorn sock Net zipper Quiver 0 Iron Game Juice 5 diamond Gem Violin zen Door Quadrilateral oyster ghost Igloo Cat Apple guitar Ink Camera Acrobat garden Ice Cake Avocado grape Iguana Cat Acrobat game Ink Computer Avocado yogurt Ink Easel Rose popcorn castle ice-cream heart zap Kitchen Star Astronaut globe Magnet jet key sock Notebook jewel Mailbox 4 Log Desk Unicorn yogurt Mask Cookie watch 4 Magnet zebra Ice garden Yurt necklace leaf 0 Zap Xylophone Mask ghost Zelda newspaper Jet lighthouse Zipper Quail 0 Kitchen Jigsaw 2 game 3 Necklace 1 Beach fire candle zombie camera zoo Newspaper Diamond Eraser 3 astronaut Horn ladybug fence camera mailbox Van 2 Uniform 0 hamburger Fox Trumpet Eagle xylitol 9 Jack-o-lantern yolk Astronaut Net Candle guitar = = 
```

I was kinda confused by htmls, so I decided to deal with texts first. It is pretty obvious, that it is some sort of encryption. One catchy thing is that there are words both starting with upper and lower case letters and there are even numbers and special characters. So the info is hidden in first charracters of every word separated by spaces. I wrote a Python script to extract only first letters:

```
with open("words.txt", "r", encoding="utf-8") as f:
    text = f.read()

# split by whitespace only
tokens = text.split()

# take first character of each token
result = ''.join(token[0] for token in tokens if len(token) > 0)

print(result)
```
And when I extracted a string from the text above I got a base64 encoded string.

```
IFZvbHVtZSBpbiBkcml2ZSBDIGhhcyBubyBsYWJlbC4NCiBWb2x1bWUgU2VyaWFsIE51bWJlciBpcyBBMDc5LUFERkINCg0KIERpcmVjdG9yeSBvZiBDOlxUZW1wDQoNCjA1LzA3LzIwMjQgIDA5OjIyIEFNICAgIDxESVI+ICAgICAgICAgIC4NCjA1LzA3LzIwMjQgIDA5OjIyIEFNICAgIDxESVI+ICAgICAgICAgIC4uDQowNS8wNy8yMDI0ICAwNzoyMyBBTSAgICAgICAgNjcsNTE1LDc0NCBzbXBob3N0LmV4ZQ0KICAgICAgICAgICAgICAgMSBGaWxlKHMpICAgICA2Nyw1MTUsNzQ0IGJ5dGVzDQogICAgICAgICAgICAgICAyIERpcihzKSAgMjksNjM4LDUyMCw4MzIgYnl0ZXMgZnJlZQ0KJ2g3N1BfczczNDE3aHlfcmV2U0hFTEx9JyANCg==
```
Now we decode it.

```
 Volume in drive C has no label.
 Volume Serial Number is A079-ADFB

 Directory of C:\Temp

05/07/2024  09:22 AM    <DIR>          .
05/07/2024  09:22 AM    <DIR>          ..
05/07/2024  07:23 AM        67,515,744 smphost.exe
               1 File(s)     67,515,744 bytes
               2 Dir(s)  29,638,520,832 bytes free
'h77P_s73417hy_revSHELL}' 
```
Wow, first part of the flag ! Now let's move to the executable. I ain't some crazy man to launch some shady staff on personal computer, so I used Detect It Easy to see if I can find something. However, it gave no results, I also got nothing from reversing it in Ghidra. So, here comes the DotPeek. I found a decomiled code of the program with a wordlist!

```
  static Program()
  {
    Dictionary<string, string> dictionary = new Dictionary<string, string>();
    dictionary.Add("cite", "0");
    dictionary.Add("h1", "1");
    dictionary.Add("p", "2");
    dictionary.Add("a", "3");
    dictionary.Add("img", "4");
    dictionary.Add("ul", "5");
    dictionary.Add("ol", "6");
    dictionary.Add("button", "7");
    dictionary.Add("div", "8");
    dictionary.Add("span", "9");
    dictionary.Add("label", "a");
    dictionary.Add("textarea", "b");
    dictionary.Add("nav", "c");
    dictionary.Add("b", "d");
    dictionary.Add("i", "e");
    dictionary.Add("blockquote", "f");
    Program.tagHex = dictionary;
  }
}
```
So now we see that every html tag can be transformed into a hex character. And html document forms a string. So now we need a script, which would transorm an html document into hex string.

```
import re

tag_map = {
    "cite": "0",
    "h1": "1",
    "p": "2",
    "a": "3",
    "img": "4",
    "ul": "5",
    "ol": "6",
    "button": "7",
    "div": "8",
    "span": "9",
    "label": "a",
    "textarea": "b",
    "nav": "c",
    "b": "d",
    "i": "e",
    "blockquote": "f"
}

with open("page.html", "r", encoding="utf-8") as f:
    html = f.read()

# extract tags in order
tags = re.findall(r"<\s*(\w+)", html)

# map tags to hex
hex_string = ""
for t in tags:
    if t in tag_map:
        hex_string += tag_map[t]

print("Hex string:", hex_string)

# decode hex → ASCII
try:
    bytes_data = bytes.fromhex(hex_string)
    print("Decoded:", bytes_data.decode(errors="ignore"))
except Exception as e:
    print("Hex decode error:", e)
```
There were multiple htmls, so the one we need was in tcp stream 4.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTML Web Server</title>
</head>
<body><ol><li>eagle horn feather zero hat acrobat</li></ol>
<img src=easel duck>
<ol><li>zigzag ink jump</li></ol>
<span>onion ninja basket watermelon wheel</span>
<button>wagon acrobat keyboard wheel quilt</button>
<p>jacket zen pyramid yellow pizza computer album penguin garden</p>
<p>tiger honey bear heart</p>
<cite>juice game pencil door helicopter quarterback wand</cite>
<p>zoo bird bottle pear ant wand</p>
<ol><li>rocket wallet owl xylitol garden gem guitar</li></ol>
<p>cloud notebook dragon</p>
<ol><li>yak ocean jewel acrobat penguin rainbow snake insect ball</li></ol>
<p>uniform table kite dog zap jacket computer anchor xerophyte</p>
<cite>pencil pumpkin candle xanthan leaf instrument vine kite feather key</cite>
<ol><li>spider</li></ol>
<a href="#">bear vase bicycle</a>
<ol><li>instrument turtle quill raccoon garden xylophone zipper pear owl</li></ol>
<img src=windmill feather mouse vegetable>
<p>nail orange volcano magnet apple vine envelope unicorn fruit cookie</p>
<cite>zero juice</cite>
<ul><li>bear utensil zone egg beach avocado</li></ul>
<nav>universe jar</nav>
<ul><li>clown yurt kettle mushroom fire monkey earth nail</li></ul>
<ul><li>knight rocket beach cat rug</li></ul>
<button>xenon clown jungle necklace microphone lemon banana kite mountain question</button>
<a href="#">nail net vine nest flag</a>
<ol><li>rug monkey</li></ol>
<ul><li>key star</li></ul>
<button>xerosis raccoon magnet ant dragon volcano</button>
<p>sandwich xerosis candle popcorn sun easel cookie plane question unicorn</p>
<button>zero xerosis ice-cream fish acrobat</button>
<a href="#">watermelon goat bicycle jump butterfly basket owl</a>
<ul><li>ring elf eraser zipper popcorn plane xylulose</li></ul>
<nav>king urn utensil tooth umbrella wheel quiver squirrel moon</nav>
<button>kite rabbit jack-o-lantern microphone penguin kettle nest otter</button>
<cite>yawn mango ocean spider engine snowman quiver</cite>
<ol><li>key candle magnet</li></ol>
<h1>dragon dinosaur</h1>
<ol><li>vacuum ring pencil tree hamburger utensil insect iron unicycle</li></ol>
<textarea>cake rocket egg goat envelope drum unicycle</textarea>
<ol><li>kayak video pineapple quadrilateral</li></ol>
<a href="#">honey wagon clown</a>
<button>nose banana instrument tiger unicycle trumpet train rocket album</button>
<span>moon</span>
<ol><li>wheel upholsterer</li></ol>
<p>jet whale iguana mask</p>
<ol><li>quarterback volcano lion</li></ol>
<ul><li>unicorn net acrobat unicycle bird panda worm ship jigsaw yodel</li></ul>
<button>yolk arrow mailbox ladder iguana quiver xebec kitchen</button>
<p>yawn candle key yodel gift butterfly</p>
<ol><li>windmill utensil quartz rose</li></ol>
<p>yurt vegetable nest</p>
<ol><li>elephant lemon jungle dog cloud arrow cake net onion mango</li></ol>
<blockquote>igloo eraser watch ladder rocket unicycle hedgehog xmas</blockquote>
<button>vine</button>
<img src=bird drum mouse otter cake acrobat goat car>
<ul><li>vine basket</li></ul>
<nav>van mailbox nut monkey pencil alarm</nav>
<img src=zombie desk elephant hammer>
<img src=oven rocket necklace umbrella computer bicycle escalator butterfly>
<ol><li>video pencil nail quartz spider ball quadrilateral</li></ol>
<blockquote>hamburger wallet tooth king yodel candle</blockquote>
<ol><li>volcano basket igloo instrument heart juice jump lemon onion</li></ol>
<a href="#">zero hat lock airplane laptop jigsaw windmill tooth banana doll</a>
<button>guitar whale x-ray candle</button>
<ul><li>basket astronaut oven sandwich</li></ul>
<ol><li>escalator easel vase quilt x-ray jet dinosaur otter nest</li></ol>
<b>jacket goat otter</b>
<ol><li>vulture invitation mountain tooth flashlight nest camera vegetable xylitol train</li></ol>
<ul><li>mouse mask cake violin volcano castle newspaper jacket</li></ul>
<ol><li>ruler lemon king banana necklace island gift spoon leaf sock</li></ol>
<i>mouse hedgehog hamburger sun beach zigzag</i>
<button>lemon leaf umbrella yucca tiger ninja</button>
<img src=wing wallet question kangaroo vine iron snake yodel knight jungle>
<button>panda</button>
<a href="#">mask noodles elf jungle spoon clown unicycle</a>
<ul><li>igloo jellyfish basket ship</li></ul>
<nav>laptop invitation cloud zap underground pyramid ninja violin fence</nav>
<p>glasses yodel umbrella</p>
<cite>lion tomato bird yellow octopus hammer lock</cite>
<p>nest</p>
<ol><li>garden windmill ninja violin elf</li></ol>
<p>unicorn tambourine fence question acrobat</p>
<ol><li>jack-o-lantern hat pyramid moon</li></ol>
<p>gift yawn horse pear grape kangaroo</p>
<cite>rocket ball ocean key turtle vegetable vest mango banana dragon</cite>
<button>owl kitchen quail star oven yawn unicorn</button>
<img src=video zebra xebec mask turtle kayak>
<button>bottle igloo trumpet leaf garden mountain video raccoon ladder engine</button>
<span>turtle diamond tooth ship yellow xmas computer monkey vacuum dog</span>
<button>ghost net invitation pear vine glasses envelope ring panda</button>
<cite>computer car grape lion yawn flag ghost table jack-o-lantern castle</cite>
<ol><li>jump horse arrow leaf mailbox</li></ol>
<ul><li>octopus</li></ul>
<p>igloo utensil quartz</p>
<cite>vine frog hamburger volcano apple zebra universe</cite>
<img src=frog flag iguana spoon lion panda kettle fence vacuum watermelon>
<div>quiver jungle ghost vest ant leaf gift tree</div>
<ul><li>cookie book zero noodles tiger helicopter xylulose quartz pencil</li></ul>
<img src=pumpkin yew dog ice-cream banana>
<img src=knight zigzag avocado quail yellow van otter rose yew universe>
<p>heart jar hamburger cloud</p>
<button>fence star gem yogurt banana</button>
<textarea>zipper vine honey zero newspaper uniform jack-o-lantern pizza trumpet</textarea>
<ul><li>quarterback hedgehog</li></ul>
<img src=horse watermelon pear van yurt tiger>
<ol><li>wagon hat lighthouse dolphin yak otter ukulele ladder</li></ol>
<div>dinosaur plane oyster zipper elf wheel garden owl desk ukulele</div>
<a href="#">cat vacuum</a>
<img src=candle banana hammer unicorn yak xmas keyboard telescope zigzag>
<button>radio urn</button>
<img src=ghost fruit quartz flashlight yodel jellyfish worm ring>
<button>fish instrument</button>
<a href="#">grape orange noodles lion yurt garden</a>
<ul><li>pumpkin hammer oyster bird honey</li></ul>
<blockquote>tree wand koala vase ball quartz</blockquote>
<ol><li>ukulele horse jungle octopus juice plane fruit bird</li></ol>
<img src=pear sock vegetable olive iron necklace flag yogurt quail radio>
<a href="#">house spoon quadrilateral avocado zombie</a>
<cite>xerosis jump pencil</cite>
<a href="#">computer drum ship watermelon quill helicopter rainbow moon</a>
<button>log noodles wand xerosis yogurt</button>
<ol><li>train camera quiver rainbow lock cake quilt dog</li></ol>
<i>nose</i>
<a href="#">rainbow knight</a>
<a href="#">keyboard xylitol zoo butterfly astronaut door beach nest x-ray</a>
<a href="#">table kangaroo snake worm wing flag</a>
<button>avocado wing moon watch invitation mango</button>
<ul><li>ant rainbow pineapple elephant ship yew clown ladder jump popcorn</li></ul>
<blockquote>wand iron video unicorn nut key yellow</blockquote>
</body>
</html>
```
Now we decode it.
```
Hex string: 646972202626206364205c55736572735c70616b6379626572626f745c446f63756d656e74735c2026262074797065204854427b54683474735f6430376e33375f
Decoded: dir && cd \Users\pakcyberbot\Documents\ && type HTB{Th4ts_d07n37_
```
And here it comes !
And as the result we got the flag: HTB{Th4ts_d07n37_h77P_s73417hy_revSHELL}.
It was a good challenge, that shows the importance of being pacient and carefuly analyze the given content. This challenge took me more time than I expected, but in future such tasks will be easier for me.
