# Vault1337
![Vault1337 logo](/vault/static/images/logos/png/logo-no-background.png "Vault1337 Logo")
## Project detail
> Firstly, I would like to shout out the [Viper-Framework](https://github.com/viper-framework) which has been the main inspiration /  motivation for this project.

> Secondly, I'm still learning so please don't harras me for my poor coding skills!

> Vault1337 is being built using the Django framework to enable me to create a repository for malware and utilise Python3 to perform static analysis on samples.

> Currently being developed on Windows but it is likely this will be better suited to run on Linx rather than Windows in order to take advantage of Linux static analysis capabilities

## TODO

- [ ] Learn Django (ongoing)
- [x] Create database
- [x] Create user registration form
- [x] Create initial templates
- [ ] Investigate potential security issues
- [x] Create vault page
- [x] Creat sample view page
- [x] Add samples to vault via file upload form
- [ ] Add archive samples and unzip via upload form
- [x] Delete samples from the vault
- [x] Add URLs to vault
- [ ] Import sample from Virus Total - requires premium account
- [ ] Add Virus Total enrichment button for samples
- [ ] Import sample from Malware Bazaar
- [ ] Add yara functionality
- [ ] Dark mode?
- [ ] Generate FUZZY hashes for samples

## Tools to add

- [x] Create basic "Strings" tool to run against samples and display the output
- [ ] MS document analysis
- [ ] PDF document analysis
- [ ] Email analysis including reputation check
- [x] Hex viewer
- [x] LIEF - Python library integration
- [ ] unpacker
- [ ] config extractor
- [ ] run custom script against sample
- [ ] Sandbox integration
- [ ] Virus Total passive checks
- [ ] Some sort of AV dcan
- [ ] EXIF data
- [ ] Flare-Floss

## Want to try it yourself?

```bash
git clone https://github.com/DanDreadless/Vault1337
pip install -r requirements.txt
```
**Generate a new APP Key for your instance and rename the .env.sample to .env and copy your new key inside**

```python
python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
```

## Django commands to remember

### Run the app server
```python
python manage.py runserver
```

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

![Vault1337 logo](/vault/static/images/screenshots/Sample_View.png "Sample View")

![Vault1337 logo](/vault/static/images/screenshots/Sample_View_Strings.png "Strings Tool In Use")

![Vault1337 logo](/vault/static/images/screenshots/Sample_View_LIEF.png "LIEF parser Tool In Use")
