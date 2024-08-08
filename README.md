![Vault1337 logo](/vault/static/images/logos/png/logo-no-background.png "Vault1337 Logo")

---

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://github.com/DanDreadless/Vault1337/blob/main/LICENSE) [![Website](https://img.shields.io/website?url=https%3A%2F%2Fwww.vault1337.com%2F&label=Vault1337&link=https%3A%2F%2Fwww.vault1337.com%2F)](https://www.vault1337.com/)
 [![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/DanDreadless?link=https%3A%2F%2Fx.com%2FDanDreadless)](https://x.com/DanDreadless)

---

## Project detail
> Firstly, I would like to shout out the [Viper-Framework](https://github.com/viper-framework) which has been the main inspiration /  motivation for this project.

> Secondly, I'm still learning so please don't harras me for my poor coding skills! yes, I am asking LLMs for help and so should you!

> Vault1337 is being built using the Django framework to enable me to create a repository for malware and utilise Python3 to perform static analysis on samples.

> Currently being developed on Windows but it is likely this will be better suited to run on Linx rather than Windows in order to take advantage of Linux static analysis capabilities ** Update ** I do have this running nicely on my Raspberry PI 5 with SSD board.

Documentation is a work in progress but can be found at [Vault1337.com](https://www.vault1337.com)

## TODO

- [ ] Learn Django (ongoing)
- [ ] Upgrade to Django 5.1 and run tests
- [ ] Create documentation (ongoign)
- [ ] Investigate potential security issues (ongoing)
- [ ] Move URL function to workbench
- [ ] Import sample from Virus Total - requires premium account (sad face)
- [ ] Limit the number of visible rows in the Vault table adding page numbers
- [ ] Add yara functionality (in progress)
- [ ] Dark mode?
- [ ] Generate FUZZY hashes for samples
- [ ] Tidy up code it is a bit of a mess
- [ ] create tabels for tags, notes and IOCs and make them relational
- [ ] Add check for the existence of the "samples" folder and create if not there
- [ ] Test Docker and running via Apache2

## Tools to create/integrate

- [ ] MS document analysis - IN PROGRESS (oletools)
- [ ] PDF document analysis - IN PROGRESS
- [ ] Email analysis including reputation check - IN PROGRESS
- [ ] Note taking feature for notes tab
- [ ] File Unzipper
- [ ] unpacker
- [ ] config extractor
- [ ] run custom script against sample (potentially dangerous, consider running inside of docker)
- [ ] Sandbox integration
- [ ] Virus Total passive checks
- [ ] Some sort of AV scan
- [ ] Flare-Floss
- [ ] AI to help describe script behaviour etc

## Tools added 

- [x] Create basic "Strings" tool to run against samples and display the output
- [x] Hex viewer
- [x] LIEF - Python library integration
- [x] EXIF data - Requires local install of [ExifTool by Phil Harvey](https://exiftool.org/)
- [x] IOC extractor (regex needs some work)

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

## Want to try it yourself?

Head over to our Documentation site for the latest install instructions [Vault1337.com](https://www.vault1337.com)

## Handy Django commands

### Delete all content for a model

```python
python manage.py shell
>> from {app_name}.models import {model_name}
>> {model_name}.objects.all().delete()
```

### View model contents

```python
python manage.py shell
>> from {app_name}.models import {model_name}
>> {model_name}.objects.all().values()
```

## Progress Screenshots

![Vault1337 logo](/vault/static/images/screenshots/Home_Screen_loggedIn.png "Home Screen Logged In")

![Vault1337 logo](/vault/static/images/screenshots/Vault.png "Vault")

![Vault1337 logo](/vault/static/images/screenshots/Vault_Actions.png "Vault")

![Vault1337 logo](/vault/static/images/screenshots/Sample_View.png "Sample View")

![Vault1337 logo](/vault/static/images/screenshots/Tool_View_Strings.png "Strings Tool In Use")

![Vault1337 logo](/vault/static/images/screenshots/Tool_View_LIEF.png "LIEF parser Tool In Use")

![Vault1337 logo](/vault/static/images/screenshots/ip_rep_1.png "IP Reputation")

![Vault1337 logo](/vault/static/images/screenshots/ip_rep_2.png "IP Reputation")
