![Vault1337 logo](/vault/static/images/logos/png/logo-no-background.png "Vault1337 Logo")
## Project detail
> Firstly, I would like to shout out the [Viper-Framework](https://github.com/viper-framework) which has been the main inspiration /  motivation for this project.

> Secondly, I'm still learning so please don't harras me for my poor coding skills! yes, I am asking LLMs for help and so should you!

> Vault1337 is being built using the Django framework to enable me to create a repository for malware and utilise Python3 to perform static analysis on samples.

> Currently being developed on Windows but it is likely this will be better suited to run on Linx rather than Windows in order to take advantage of Linux static analysis capabilities ** Update ** I do have this running nicely on my Raspberry PI 5 with SSD board.

Documentation is a work in progress but can be found at [Vault1337.com](https://www.vault1337.com)

## TODO

- [ ] Learn Django (ongoing)
- [ ] Create documentation
- [ ] Investigate potential security issues (ongoing)
- [ ] Move URL function to workbench
- [ ] Import sample from Virus Total - requires premium account (sad face)
- [ ] Create "Actions" dropdown in vault table
- [ ] Add yara functionality
- [ ] Dark mode?
- [ ] Generate FUZZY hashes for samples
- [ ] Get tags working properly so they are searchable
- [ ] Tidy up code it is a bit of a mess
- [ ] create tabels for tags, notes and IOCs and make them relational

## Tools to create/integrate

- [ ] MS document analysis - IN PROGRESS (oletools)
- [ ] PDF document analysis - IN PROGRESS
- [ ] Email analysis including reputation check
- [ ] IOC extractor for IOC tab
- [ ] Note taking feature for notes tab
- [ ] File Unzipper
- [ ] unpacker
- [ ] config extractor
- [ ] run custom script against sample (potentially dangerous, consider running inside of docker)
- [ ] Sandbox integration
- [ ] Virus Total passive checks
- [ ] Some sort of AV dcan
- [ ] Flare-Floss
- [ ] AI to help describe script behaviour etc

## Tools added 

- [x] Create basic "Strings" tool to run against samples and display the output
- [x] Hex viewer
- [x] LIEF - Python library integration
- [x] EXIF data - Requires local install of [ExifTool by Phil Harvey](https://exiftool.org/)

##  Completed

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

## Want to try it yourself?

**Download the vault**

```bash
git clone https://github.com/DanDreadless/Vault1337
sudo chown -R your_user:your_user Vault1337/
cd Vault1337/
```

**Create python venv**

```python
python3 -m venv ~/vault1337
source ~/vault1337/bin/activate
pip install -r requirements.txt
```

**Generate a new APP Key for your instance and rename the .env.sample to .env and copy your new key inside**

```python
python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
```

**Initialise database**

```python
python3 manage.py makemigrations
python3 manage.py migrate
```

**Create SuperUser**

```python
python3 manage.py createsuperuser
```

**You're good to go! Run the app server**

```python
python3 manage.py runserver
```

## Django commands to remember


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

![Vault1337 logo](/vault/static/images/screenshots/Tool_View_Strings.png "Strings Tool In Use")

![Vault1337 logo](/vault/static/images/screenshots/Tool_View_LIEF.png "LIEF parser Tool In Use")
