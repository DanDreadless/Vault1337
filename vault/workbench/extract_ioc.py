import re
from typing import List, Dict
from vault.models import File, IOC

# Valid TLDs list as of 23/05/2025
VALID_TLDS = {
    "aaa", "aarp", "abarth", "abb", "abbott", "abbvie", "abc", "able", "abogado",
    "abudhabi", "ac", "academy", "accenture", "accountant", "accountants", "aco",
    "active", "actor", "ad", "adac", "ads", "adult", "ae", "aeg", "aero", "aetna",
    "af", "afamilycompany", "afl", "ag", "agakhan", "agency", "ai", "aig", "aigo",
    "airbus", "airforce", "airtel", "akdn", "al", "alfaromeo", "alibaba", "alipay",
    "allfinanz", "allstate", "ally", "alsace", "alstom", "am", "americanexpress",
    "americanfamily", "amex", "amfam", "amica", "amsterdam", "an", "analytics",
    "android", "anquan", "anz", "ao", "aol", "apartments", "app", "apple", "aq",
    "aquarelle", "ar", "aramco", "archi", "army", "arpa", "art", "arte", "as",
    "asda", "asia", "associates", "at", "athleta", "attorney", "au", "auction",
    "audi", "audible", "audio", "auspost", "author", "auto", "autos", "avianca",
    "aw", "aws", "ax", "axa", "az", "azure", "ba", "baby", "baidu", "banamex",
    "bananarepublic", "band", "bank", "bar", "barcelona", "barclaycard", "barclays",
    "barefoot", "bargains", "baseball", "basketball", "bauhaus", "bayern", "bb",
    "bbc", "bbt", "bbva", "bcg", "bcn", "bd", "be", "beats", "beauty", "beer",
    "bentley", "berlin", "best", "bestbuy", "bet", "bf", "bg", "bh", "bharti",
    "bi", "bible", "bid", "bike", "bing", "bingo", "bio", "biz", "bj", "black",
    "blackfriday", "blanco", "blockbuster", "blog", "bloomberg", "blue", "bms",
    "bmw", "bn", "bnl", "bnpparibas", "bo", "boats", "boehringer", "bofa", "bom",
    "bond", "boo", "book", "booking", "boots", "bosch", "bostik", "boston",
    "bot", "boutique", "box", "br", "bradesco", "bridgestone", "broadway", "broker",
    "brother", "brussels", "bs", "bt", "budapest", "bugatti", "build", "builders",
    "business", "buy", "buzz", "bv", "bw", "by", "bz", "bzh", "ca", "cab", "cafe",
    "cal", "call", "calvinklein", "cam", "camera", "camp", "cancerresearch",
    "canon", "capetown", "capital", "car", "caravan", "cards", "care", "career",
    "careers", "cars", "cartier", "casa", "cash", "casino", "cat", "catering",
    "catholic", "cba", "cbn", "cc", "cd", "ceb", "center", "ceo", "cern", "cf",
    "cfa", "cfd", "cg", "ch", "chanel", "channel", "charity", "chase", "chat",
    "cheap", "chintai", "chloe", "christmas", "chrome", "chrysler", "chungkuo",
    "ci", "cipriani", "circle", "cisco", "citadel", "citi", "citic", "city",
    "cityeats", "ck", "cl", "claims", "cleaning", "click", "clinic", "clinique",
    "clothing", "cloud", "club", "clubmed", "cm", "cn", "co", "coach", "codes",
    "coffee", "college", "cologne", "com", "comcast", "commbank", "community",
    "company", "compare", "computer", "comsec", "condos", "construction",
    "consulting", "contact", "contractors", "cooking", "cookingchannel",
    "cool", "coop", "corsica", "country", "coupon", "coupons", "courses",
    "cpa", "cr", "credit", "creditcard", "creditunion", "cricket", "crown",
    "crs", "cruise", "cruises", "cu", "cuisinella", "cv", "cw", "cx", "cy",
    "cymru", "cyou", "cz", "dabur", "dad", "dance", "data", "date", "dating",
    "datsun", "day", "dclk", "dds", "de", "deal", "dealer", "deals", "degree",
    "delivery", "dell", "deloitte", "delta", "democrat", "dental", "dentist",
    "desi", "design", "dev", "dhl", "diamonds", "diet", "digital", "direct",
    "directory", "discount", "discover", "dish", "diy", "dj", "dk", "dm",
    "dnp", "do", "docs", "doctor", "dodge", "dog", "doha", "domains", "dot",
    "download", "drive", "dtv", "dubai", "duck", "dunlop", "duns", "dupont",
    "durban", "dvag", "dz", "eat", "ec", "eco", "edeka", "edu", "education",
    "ee", "eg", "email", "emerck", "energy", "engineer", "engineering",
    "enterprises", "epost", "epson", "equipment", "er", "ericsson", "erni",
    "es", "esq", "estate", "esurance", "et", "etisalat", "eu", "eurovision",
    "eus", "events", "everbank", "exchange", "expert", "exposed", "express",
    "extraspace", "fage", "fail", "fairwinds", "faith", "family", "fan",
    "fans", "farm", "fashion", "fast", "fedex", "feedback", "ferrari",
    "ferrero", "fi", "fidelity", "fido", "film", "final", "finance", "financial",
    "fire", "firestone", "firmdale", "fish", "fishing", "fit", "fitness",
    "fj", "fk", "flickr", "flights", "florist", "flowers", "fly", "fm", "fo",
    "foo", "food", "foodnetwork", "football", "ford", "forex", "forsale",
    "forum", "foundation", "fox", "fr", "free", "fresenius", "frl", "frogans",
    "frontdoor", "frontier", "ftr", "fund", "furniture", "futbol", "fyi",
    "ga", "gal", "gallery", "gallo", "gallup", "game", "games", "gap",
    "garden", "gay", "gb", "gbiz", "gd", "gdn", "ge", "gea", "gent", "genting",
    "george", "ggee", "gg", "gi", "gift", "gifts", "gives", "giving", "gl",
    "glade", "glass", "gle", "global", "globo", "gm", "gmail", "gmbh",
    "gmo", "gmX", "gn", "godaddy", "gold", "goldpoint", "golf", "goo",
    "goodyear", "goog", "google", "gop", "got", "gov", "gp", "gq", "gr",
    "grainger", "graphics", "gratis", "green", "gripe", "group", "gs",
    "gt", "gu", "guardian", "gucci", "guge", "guide", "guitars", "guru",
    "gw", "gy", "hamburg", "hangout", "haus", "hbo", "hdfc", "hdfcbank",
    "health", "healthcare", "help", "helsinki", "here", "hermes", "hgtv",
    "hiphop", "hisamitsu", "hitachi", "hiv", "hk", "hkt", "hm", "hn",
    "hockey", "holdings", "holiday", "homedepot", "homegoods", "homes",
    "homesense", "honda", "horse", "hospital", "host", "hosting", "hot",
    "hoteles", "hotels", "hotmail", "house", "how", "hr", "hsbc", "ht",
    "hu", "hughes", "hyatt", "hyundai", "ibm", "icbc", "ice", "icu",
    "id", "ie", "ieee", "ifm", "iinet", "ikano", "il", "im", "imamat",
    "imdb", "immo", "immobilien", "in", "inc", "industries", "infiniti",
    "info", "ing", "ink", "institute", "insurance", "insure", "int",
    "international", "investments", "io", "ipiranga", "iq", "ir", "irish",
    "is", "iselect", "ismaili", "ist", "istanbul", "it", "itau", "itv",
    "jaguar", "java", "jcb", "jcp", "je", "jeep", "jetzt", "jewelry",
    "jio", "jlc", "jll", "jm", "jmp", "jnj", "jo", "jobs", "joburg",
    "jot", "joy", "jp", "jpmorgan", "jprs", "juegos", "juniper", "kaiser",
    "kaufen", "kddi", "ke", "kerryhotels", "kerrylogistics", "kerryproperties",
    "kfh", "kg", "kh", "ki", "kia", "kim", "kinder", "kindle", "kitchen",
    "kiwi", "km", "kn", "koeln", "komatsu", "kosher", "kp", "kpmg", "kpn",
    "kr", "krd", "kred", "kw", "ky", "kyoto", "kz", "la", "lacaixa",
    "ladbrokes", "lamborghini", "lamer", "lancaster", "lancia", "lancome",
    "land", "landrover", "lanxess", "lasalle", "lat", "latino", "latrobe",
    "law", "lawyer", "lb", "lc", "lds", "lease", "leclerc", "lefrak",
    "legal", "lego", "lexus", "lgbt", "li", "liaison", "lidl", "life",
    "lifeinsurance", "lifestyle", "lighting", "like", "lilly", "limited",
    "limo", "lincoln", "linde", "link", "lipsy", "live", "living", "lixil",
    "lk", "llc", "llp", "loan", "loans", "locker", "locus", "lol", "london",
    "lotte", "lotto", "love", "lpl", "lplfinancial", "lr", "ls", "lt",
    "ltd", "ltda", "lu", "lundbeck", "lupin", "luxe", "luxury", "lv", "ly",
    "ma", "madrid", "maif", "maison", "makeup", "man", "management", "mango",
    "map", "market", "marketing", "markets", "marriott", "marshalls",
    "maserati", "mattel", "mba", "mc", "md", "me", "med", "media", "meet",
    "melbourne", "meme", "memorial", "men", "menu", "meo", "merckmsd",
    "metlife", "mg", "mh", "miami", "microsoft", "mil", "mini", "mint",
    "mit", "mitsubishi", "mk", "ml", "mlb", "mls", "mm", "mma", "mn",
    "mo", "mobi", "mobile", "moda", "moe", "moi", "mom", "monash",
    "money", "monster", "mopar", "mormon", "mortgage", "moscow",
    "moto", "motorcycles", "mov", "movie", "mp", "mq", "mr", "ms",
    "msd", "mt", "mtn", "mtr", "mu", "museum", "mutual", "mv", "mw",
    "mx", "my", "mz", "na", "nab", "nagoya", "name", "natura", "navy",
    "nba", "nc", "ne", "nec", "net", "netbank", "network", "neustar",
    "new", "newholland", "news", "next", "nextdirect", "nexus",
    "nf", "ng", "ngo", "nhk", "ni", "nico", "nike", "nikon", "ninja",
    "nissan", "nissay", "nl", "no", "nokia", "northwesternmutual",
    "norton", "now", "nowruz", "nowtv", "np", "nr", "nra", "nrw", "ntt",
    "nu", "nyc", "nz", "obi", "observer", "off", "office", "okinawa",
    "olayan", "olayangroup", "oldnavy", "ollo", "om", "omega", "one",
    "ong", "onl", "online", "ooo", "open", "oracle", "orange", "org",
    "organic", "orientexpress", "origins", "osaka", "otsuka", "ott",
    "ovh", "pa", "page", "pamperedchef", "panerai", "paris", "pars",
    "partners", "parts", "party", "passagens", "pay", "pccw", "pet",
    "pf", "pfizer", "pg", "ph", "pharmacy", "phd", "philips", "phone",
    "photo", "photography", "photos", "physio", "piaget", "pics", "pictet",
    "pictures", "pid", "pin", "ping", "pink", "pioneer", "pizza", "pk",
    "pl", "place", "play", "playstation", "plumbing", "plus", "pm",
    "pn", "pnc", "pohl", "poker", "politie", "porn", "post", "pr",
    "praxi", "press", "prime", "pro", "prod", "productions", "prof",
    "progressive", "promo", "properties", "property", "protection",
    "pru", "prudential", "ps", "pt", "pub", "pw", "pwc", "py", "qa",
    "qpon", "quebec", "quest", "racing", "radio", "raid", "re", "read",
    "realestate", "realtor", "realty", "recipes", "red", "redstone",
    "redumbrella", "rehab", "reise", "reisen", "reit", "reliance",
    "ren", "rent", "rentals", "repair", "report", "republican",
    "rest", "restaurant", "review", "reviews", "rexroth", "rich",
    "richardli", "ricoh", "rightathome", "ril", "rio", "rip", "rmit",
    "ro", "rocher", "rocks", "rodeo", "rogers", "room", "rs", "rsvp",
    "ru", "rugby", "ruhr", "run", "rw", "rwe", "ryukyu", "sa", "saarland",
    "safe", "safety", "sakura", "sale", "salon", "samsclub", "samsung",
    "sandvik", "sandvikcoromant", "sanofi", "sap", "sapo", "sarl",
    "sas", "save", "saxo", "sb", "sbi", "sbs", "sc", "sca", "scb",
    "schaeffler", "schmidt", "scholarships", "school", "schule",
    "schwarz", "science", "scjohnson", "scor", "scot", "sd", "se",
    "search", "seat", "secure", "security", "seek", "select", "sener",
    "services", "ses", "seven", "sew", "sex", "sexy", "sfr", "sg",
    "sh", "shangrila", "sharp", "shaw", "shell", "shia", "shiksha",
    "shoes", "shop", "shopping", "shouji", "show", "showtime", "si",
    "silk", "sina", "singles", "site", "ski", "skin", "sky", "skype",
    "sl", "sling", "sm", "smart", "smile", "sn", "sncf", "so", "soccer",
    "social", "softbank", "software", "sohu", "solar", "solutions",
    "song", "sony", "soy", "spa", "space", "spiegel", "spot", "spreadbetting",
    "sr", "srt", "ss", "st", "stada", "staples", "star", "starhub",
    "statebank", "statefarm", "stc", "stcgroup", "stockholm", "storage",
    "store", "stream", "studio", "study", "style", "su", "sucks", "supplies",
    "supply", "support", "surf", "surgery", "suzuki", "sv", "swatch",
    "swiftcover", "swiss", "sx", "sy", "sydney", "symantec", "systems",
    "sz", "tab", "taipei", "talk", "taobao", "target", "tatamotors",
    "tatar", "tattoo", "tax", "taxi", "tc", "tci", "td", "tdk", "team",
    "tech", "technology", "tel", "telecity", "telefonica", "temasek",
    "tennis", "teva", "tf", "tg", "th", "thd", "theater", "theatre",
    "tiaa", "tickets", "tienda", "tiffany", "tips", "tires", "tirol",
    "tj", "tk", "tkmaxx", "tl", "tm", "tmall", "tn", "to", "today",
    "tokyo", "tools", "top", "toray", "toshiba", "total", "tours",
    "town", "toyota", "toys", "tr", "trade", "trading", "training",
    "travel", "travelchannel", "travelers", "travelersinsurance",
    "trust", "trv", "tt", "tube", "tui", "tunes", "tushu", "tv",
    "tvs", "tw", "tz", "ua", "ubank", "ubs", "uconnect", "ug", "uk",
    "unicom", "university", "uno", "uol", "ups", "us", "uy", "uz",
    "va", "vacations", "vana", "vanguard", "vc", "ve", "vegas", "ventures",
    "verisign", "versicherung", "vet", "vg", "vi", "viajes", "video",
    "vig", "viking", "villas", "vin", "vip", "virgin", "visa", "vision",
    "vistaprint", "viva", "vivo", "vu", "vuelos", "wales", "walmart",
    "walter", "wang", "wanggou", "watch", "watches", "weather", "weatherchannel",
    "webcam", "weber", "website", "wed", "wedding", "weibo", "weir",
    "whoswho", "wien", "wiki", "williamhill", "win", "windows", "wine",
    "winners", "wme", "wolterskluwer", "woodside", "work", "works",
    "world", "wow", "ws", "wtc", "wtf", "xbox", "xerox", "xfinity",
    "xihuan", "xin", "xn--11b4c3d", "xn--1ck2e1b", "xn--1qqw23a",
    "xn--2scrj9c", "xn--30rr7y", "xn--3bst00m", "xn--3ds443g",
    "xn--3e0b707e", "xn--3pxu8k", "xn--42c2d9a", "xn--45brj9c",
    "xn--45q11c", "xn--4dbrk0ce", "xn--4gbrim", "xn--54b7fta0cc",
    "xn--55qw42g", "xn--55qx5d", "xn--6frz82g", "xn--6qq986b3xl",
    "xn--80adxhks", "xn--80ao21a", "xn--80aqecdr1a", "xn--80asehdb",
    "xn--80aswg", "xn--8y0a063a", "xn--90a3ac", "xn--90ae", "xn--90ais",
    "xn--9dbq2a", "xn--9et52u", "xn--9krt00a", "xn--b4w605ferd",
    "xn--bck1b9a5dre4c", "xn--c1avg", "xn--c2br7g", "xn--cck2b3b",
    "xn--cg4bki", "xn--clchc0ea0b2g2a9gcd", "xn--czr694b", "xn--czrs0t",
    "xn--d1acj3b", "xn--d1alf", "xn--e1a4c", "xn--eckvdtc9d", "xn--efvy88h",
    "xn--fct429k", "xn--fhbei", "xn--fiq228c5hs", "xn--fiq64b",
    "xn--fiqs8s", "xn--fiqz9s", "xn--fjq720a", "xn--flw351e", "xn--fpcrj9c3d",
    "xn--fzc2c9e2c", "xn--fzys8d69uvgm", "xn--g2xx48c", "xn--gckr3f0f",
    "xn--gecrj9c", "xn--gk3at1e", "xn--h2brj9c", "xn--hxt814e",
    "xn--i1b6b1a6a2e", "xn--io0a7i", "xn--j1amh", "xn--j6w193g",
    "xn--jlq480n2rg", "xn--jlq61u9w7b", "xn--jvr189m", "xn--kcrx77d1x4a",
    "xn--kprw13d", "xn--kpry57d", "xn--kpu716f", "xn--kput3i", "xn--l1acc",
    "xn--lgbbat1ad8j", "xn--mgb9awbf", "xn--mgba3a4f16a",
    "xn--mgba3a4fra", "xn--mgba7c0bbn0a", "xn--mgbaam7a8h",
    "xn--mgbab2bd", "xn--mgbayh7gpa", "xn--mgbbh1a71e", "xn--mgbbh1a71e1f",
    "xn--mgbc0a9azcg", "xn--mgbpl2fh", "xn--mgbx4cd0ab", "xn--mix082f",
    "xn--mk1bu44c", "xn--mxtq1m", "xn--ngbc5azd", "xn--ngbe9e0a",
    "xn--node", "xn--nqv7f", "xn--nqv7fs00ema", "xn--o3cw4h", "xn--ogbpf8fl",
    "xn--p1acf", "xn--p1ai", "xn--pbt977c", "xn--pgbs0dh", "xn--pssy2u",
    "xn--q7ce6a", "xn--q9jyb4c", "xn--qcka1pmc", "xn--qxam",
    "xn--rhqv96g", "xn--rovu88b", "xn--rvc1e0am3e", "xn--s9brj9c",
    "xn--ses554g", "xn--t60b56a", "xn--tckwe", "xn--unup4y",
    "xn--vermgensberater-ctb", "xn--vermgensberatung-pwb",
    "xn--vhquv", "xn--w4r85el8fhu5dnra", "xn--w4rs40l", "xn--wgbl6a",
    "xn--xhq521b", "xn--xkc2al3hye2a", "xn--xkc2dl3a5ee0h", "xn--y9a3aq",
    "xn--yfro4i67o", "xn--ygbi2ammx", "xxx", "xyz", "yachts",
    "yahoo", "yamaxun", "yandex", "yodobashi", "yoga", "yokohama",
    "you", "youtube", "yt", "yun", "za", "zappos", "zara", "zero",
    "zip", "zippo", "zm", "zone", "zuerich", "zw"
}

# Regex patterns
IOC_PATTERNS = {
    "ip": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
    ),
    "email": re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b',
        re.IGNORECASE
    ),
    "url": re.compile(
        r'\b((?:http|https|ftp)://[^\s/$.?#].[^\s]*)\b',
        re.IGNORECASE
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}\.)+(?P<tld>[a-zA-Z]{2,})\b'
    ),
}


def extract_valid_domains(text: str) -> List[str]:
    """Filter domain matches by valid TLDs and avoid .dll false positives."""
    matches = IOC_PATTERNS["domain"].finditer(text)
    domains = set()

    for match in matches:
        domain = match.group(0).lower()
        tld = match.group("tld").lower()

        if domain.endswith(".dll") or tld not in VALID_TLDS:
            continue

        domains.add(domain)

    return sorted(domains)


def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """Extract and validate IOCs from a text block."""
    return {
        "ip": sorted(set(IOC_PATTERNS["ip"].findall(text))),
        "email": sorted(set(IOC_PATTERNS["email"].findall(text))),
        "url": sorted(set(IOC_PATTERNS["url"].findall(text))),
        "domain": extract_valid_domains(text)
    }


def format_iocs(iocs: Dict[str, List[str]]) -> str:
    """Human-readable IOC formatter."""
    lines = []
    for key in ["ip", "domain", "email", "url"]:
        lines.append(f"{key}:")
        values = iocs.get(key, [])
        if values:
            lines.extend([f"  - {value}" for value in values])
        else:
            lines.append("  - None")
    return "\n".join(lines)


def extract_and_save_iocs(file_path: str) -> str:
    """Extract IOCs from file and associate new ones with DB file."""
    try:
        sha256 = file_path.split("/")[-1]
        file = File.objects.get(sha256=sha256)
    except File.DoesNotExist:
        return "error:\n  - No file found with SHA256: {}".format(sha256)

    if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        return "error:\n  - Invalid SHA256 format."

    try:
        with open(f"vault/samples/{sha256}", "r", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        return "error:\n  - Sample file not found."

    iocs = extract_iocs_from_text(content)
    existing = set(file.iocs.values_list("value", flat=True))

    for ioc_type, values in iocs.items():
        for value in values:
            if value in existing:
                continue
            ioc, _ = IOC.objects.get_or_create(type=ioc_type, value=value)
            ioc.files.add(file)

    return format_iocs(iocs)
