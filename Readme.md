# Django Restricted Countries Middleware

This Django middleware restricts access to your application based on the geographical location of the user’s IP address. Using **GeoIP2** and **ipware**, this middleware can block users from specific countries and return a customizable forbidden message.

---

## Features

- **Country-Based Restrictions**: Blocks users based on their IP geolocation.
- **Customizable Settings**: Block specific countries and customize the forbidden message.
- **GeoIP2 Integration**: Uses **GeoIP2** for geolocation.
- **IP Address Retrieval**: Handles IP address detection, including cases with proxies using **ipware**.

---

## Requirements
============

- Django 3.1 or later.
- `Django IPWare`_ 2.1.0 or later.
- `GeoIP2`_ 2.9.0 or later.
- `MaxMind GeoLite2 country datasets`_.

## Installation

1. Install Django Restricted Countries from PyPI by using ``pip``::

    pip install restricted_countries

### 1. Install Dependencies

This middleware requires **GeoIP2** for IP geolocation and **ipware** for retrieving the client’s IP address.

#### **Install GeoIP2**:

To install **GeoIP2**:

```bash
pip install geoip2

# Setting up GeoIP2 City and Country Database

This guide explains how to set up the **GeoIP2 City and Country database** in your Django project. MaxMind's **GeoIP2** database provides geolocation information about IP addresses, including country and city details. You can use this database to restrict access based on a user's location, retrieve detailed geolocation information, and enhance your web application.

---

## Prerequisites

Before setting up the **GeoIP2 database**, ensure that:

- You have a Django project set up.
- You have **GeoIP2** installed. If not, install it via pip:
  
- You have a MaxMind account. You can sign up here: [text](https://www.maxmind.com/en/geoip-databases)
- After downloading the files
- tar -xvzf GeoLite2-Country.tar.gz -C ./geoip
- tar -xvzf GeoLite2-City.tar.gz -C ./geoip


- You have to add that to your settings file assuming you have the db files in a folder named geoip in the root folder

import os

GEOIP_PATH = os.path.join(BASE_DIR, 'geoip')

2.Install the MaxMind® GeoIP2 datasets. You can do this in two ways:

2.1. By running the provided management command for this::

    python manage.py install_geoip_dataset


2.2. Or manually, by following the instructions in `GeoIP2 Django documentation`_.

After following those steps, you should be ready to go.


3.Install ipware:
- To install ipware which helps retrieve the user's real IP, especially when they are behind a proxy:

``pip install ipware



#### **Usage**:
settings.py

MIDDLEWARE = [
    ...
    'restricted_countries.middleware.RestricedCountriesMiddleware',
    ...
]

DJANGO_RESTRICTED_COUNTRIES = {
    "COUNTRIES": ['CN', 'RU'],
    "FORBIDDEN_MSG": "Access is denied from your country."
}
