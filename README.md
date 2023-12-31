# Vault1337
![Vault1337 logo](/vault/static/images/logos/png/logo-no-background.png "Vault1337 Logo")
## Project detail
> Firstly, I would like to shout out the [Viper-Framework](https://github.com/viper-framework) which has been the main inspiration /  motivation for this project.

> Vault1337 is being built using the Django framework to enable me to create a repository for malware and utilise Python3 to perform static analysis on samples

## TODO

- [ ] Learn Django (ongoing)
- [x] Create database
- [x] Create Admin user
- [x] Create user registration form
- [x] Create initial templates
- [ ] Investigate potential security issues
- [x] Create vault page
- [x] Creat sample view page
- [x] Add samples to vault via file upload form
- [x] Add URLs to vault
- [ ] Import sample from Virus Total
- [ ] Import sample from Malware Bazaar
- [ ] Add yara functionality
- [ ] Add sessions
- [ ] Dark mode?

## Tools to add

- [x] Create basic "Strings" tool to run against samples and display the output
- [ ] MS document analysis
- [ ] PDF document analysis
- [ ] Email analysis including reputation check
- [ ] Hex viewer
- [ ] unpacker
- [ ] config extractor
- [ ] run custom script against sample
- [ ] Sandbox integration
- [ ] Virus Total passive checks
- [ ] Some sort of AV dcan

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