![Vault1337 logo](/vault/static/images/logos/png/logo-no-background.png "Vault1337 Logo")

---

[![License](https://img.shields.io/badge/AGPL-3.0--Clause-blue.svg)](https://github.com/DanDreadless/Vault1337/blob/main/LICENSE) [![Website](https://img.shields.io/website?url=https%3A%2F%2Fwww.vault1337.com%2F&label=Vault1337&link=https%3A%2F%2Fwww.vault1337.com%2F)](https://www.vault1337.com/)
 [![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/DanDreadless?link=https%3A%2F%2Fx.com%2FDanDreadless)](https://x.com/DanDreadless)

---

Vault1337 is an open-source malware analysis and repository platform designed for researchers, educators, and security enthusiasts.

## Project detail
> Firstly, I would like to shout out the [Viper-Framework](https://github.com/viper-framework) which has been the main inspiration /  motivation for this project.

> Secondly, I'm still learning so please don't harras me for my poor coding skills! yes, I am asking LLMs for help and so should you! - (SNYK backup to help reduce vulnerable code from LLMs)

> Vault1337 is being built using the Django framework (5.1.4) to enable me to create a repository for malware and utilise Python3 to perform static analysis on samples.

> Currently being developed on Windows but it is likely this will be better suited to run on Linx rather than Windows in order to take advantage of Linux static analysis capabilities
>  ** Update ** I do have this running nicely on my Raspberry PI 5 with SSD board. Served via Gunicorn/NGINX

Documentation is a work in progress but can be found at [Vault1337.com](https://www.vault1337.com)

---

## License

This project is licensed under the **GNU Affero General Public License (AGPL-3.0)**. This ensures that:
- You are free to use, modify, and share this software as long as you comply with the terms of the AGPL-3.0.
- If you deploy this software on a server, you must make the source code, including any modifications, available to your users under the same license.

The full text of the AGPL-3.0 license is available in the [LICENSE](LICENSE) file.

## Commercial Use

Vault1337 is open-source software, but we recognize that businesses may want to use it without adhering to the AGPL's strict copyleft requirements (e.g., making modifications publicly available). To accommodate such use cases, we offer a **commercial license** at a fair price.

### Benefits of the Commercial License:
1. Use Vault1337 in proprietary environments without the need to open-source your modifications.
2. Support the continued development and maintenance of the project.

### Pricing
The commercial license is available for a one-time fee. Pricing is tailored to the size and needs of your organization. Contact me for details.

## How to Purchase a Commercial License
If your organization is interested in obtaining a commercial license, please reach out to me at:

**LinkedIn:** - www.linkedin.com/in/dan-pickering

## Supporting the Project
Even if you don’t require a commercial license, consider supporting the project through donations or sponsorship. Your contributions help us improve Vault1337 and keep it free for the open-source community.

Thank you for using Vault1337!

---

## TODO

- [ ] Learn Django (ongoing)
- [ ] Create documentation (ongoign)
- [ ] Investigate potential security issues (ongoing with SNYK VSCode Plugin)
- [ ] Move URL function to workbench
- [ ] Sample view to have sha256 in url rather than database id
- [ ] IOC extractor to populate the ioc tab for sample
- [ ] Import sample from Virus Total - requires premium account (sad face)
- [ ] Limit the number of visible rows in the Vault table adding page numbers
- [ ] Add yara functionality (in progress)
- [ ] Dark mode?
- [ ] Generate FUZZY hashes for samples
- [ ] Tidy up code it is a bit of a mess
- [ ] create tabels for tags, notes and IOCs and make them relational
- [ ] Add check for the existence of the "samples" folder and create if not there
- [ ] Test Docker and running via Gunicorn
- [ ] Telegram token analysis

## Tools to create/integrate

- [ ] MS document analysis - IN PROGRESS (oletools)
- [ ] PDF document analysis - IN PROGRESS
- [ ] Email analysis including reputation check - IN PROGRESS
- [ ] Note taking feature for notes tab
- [ ] File Unzipper - Part complete
- [ ] unpacker
- [ ] config extractor
- [ ] run custom script against sample (potentially dangerous, consider running inside of docker)
- [ ] Sandbox integration
- [ ] Virus Total passive checks
- [ ] Some sort of AV scan
- [ ] Flare-Floss
- [ ] AI to help describe script behaviour etc
- [ ] integrate Javascript deobfuscation (https://github.com/ben-sb/obfuscator-io-deobfuscator)

## Tools added 

- [x] Create basic "Strings" tool to run against samples and display the output
- [x] Hex viewer
- [x] LIEF - Python library integration
- [x] EXIF data - Requires local install of [ExifTool by Phil Harvey](https://exiftool.org/)
- [x] IOC extractor (regex needs some work)
- [x] Ability to run YARA scripts against samples (still neeeds work but a good start)
- [x] Email parser (headers and content need to add attachment extraction) 

##  Completed

- [x] Add tags cloud under vault table that are clickable for filtering
- [x] Create "Actions" dropdown in vault table
- [x] Get tags working properly so they are searchable (Django-Taggit)
- [x] Create initial database
- [x] Create user registration form
- [x] Create initial templates
- [x] Create vault page
- [x] Creat sample view page
- [x] Add samples to vault via file upload form
- [x] Add archive samples and unzip via upload form - STILL NEEDS WORK
- [x] Delete samples from the vault
- [x] Add URLs to vault
- [X] Download files from URLs
- [x] Run on home Raspberry PI 5
- [x] Add Virus Total link from samples
- [x] Import sample from Malware Bazaar
- [x] IP Reputation lookup
- [x] Upgrade to Django 5.1 and run tests

## Want to try it yourself?

Head over to the Documentation site for the latest install instructions [Vault1337.com](https://www.vault1337.com)

## Progress Screenshots

![Vault1337 logo](/vault/static/images/screenshots/Home_Screen_loggedIn.png "Home Screen Logged In")

![Vault1337 logo](/vault/static/images/screenshots/Vault.png "Vault")

![Vault1337 logo](/vault/static/images/screenshots/Sample_View.png "Sample View")

![Vault1337 logo](/vault/static/images/screenshots/Tool_List.png "List Of Tools Available")

![Vault1337 logo](/vault/static/images/screenshots/Tool_View_Strings.png "Strings Tool In Use")

![Vault1337 logo](/vault/static/images/screenshots/Tool_View_LIEF.png "LIEF parser Tool In Use")

![Vault1337 logo](/vault/static/images/screenshots/Tool_View_EIOC.png "IOC Extractor Tool In Use")

![Vault1337 logo](/vault/static/images/screenshots/Sample_IOCs.png "View Of Extracted IOCs For Sample")

![Vault1337 logo](/vault/static/images/screenshots/IOCs.png "Full IOC Table")

![Vault1337 logo](/vault/static/images/screenshots/create_yara.png "Yara")

![Vault1337 logo](/vault/static/images/screenshots/ip_rep_1.png "IP Reputation")

![Vault1337 logo](/vault/static/images/screenshots/ip_rep_2.png "IP Reputation")

![Vault1337 logo](/vault/static/images/screenshots/Manage_Keys.png "Manage API Keys")
