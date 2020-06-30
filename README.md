# Yara AUCR Plugin

## Overview

This is a basic Yara Plugin that uses the AUCR web framework

### Required AUCR Plugins

-   aucr core
-   unum


### Optional AUCR Plugins

-   cuckoo_plugin
-   ids_plugin


## Developer setup

Example Setup with a docker container

    git clone https://github.com/aucr/yara_plugin
    cd yara_plugin/docs
    docker build . -t yara_aucr

## Easy Docker use

    sudo docker run yara_aucr -p 5000:5000

## Environment Variables

Here is an example env variables the aucr flask app will need. I use aucr.local as my host for all systems but normally
in a production environment.

### Required Services

-   RabbitMQ
-   Database

### Optional Services

-   Elasticsearch

Example: Environment Variables

        LC_ALL=C.UTF-8
        LANG=C.UTF-8
        RABBITMQ_SERVER=aucr.local
        RABBITMQ_PORT=5672
        RABBITMQ_USERNAME=username
        RABBITMQ_PASSWORD=password
        ELASTICSEARCH_URL=http://aucr.local:9200
        POSTS_PER_PAGE=5
        DATABASE_URL=postgresql://username:password@aucr.local:5432/aucr
        ZIP_PASSWORD=infected
        FILE_FOLDER=/opt/aucr/upload/
        SECRET_KEY=some_thing_very_random_like_L23noSDONFSD8324809nsdf
        MAIL_SERVER=smtp.gmail.com
        MAIL_PORT=587
        MAIL_USERNAME=some_user_name_@gmail.com
        MAIL_PASSWORD=some_api_app_password_for_account
        ALLOWED_EXTENSIONS=['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'exe', 'yar', 'zip', 'dll', 'rar', '']
        PRIVACY_POLICY_URL=https://app.termly.io/document/privacy-policy/ccb75cb3-f03e-43b6-bd09-de3b8c9e4d48
        MAIL_USE_TLS=True
        ALLOWED_EMAIL_LIST=gmail.com
        APP_TITLE=AUCR
        SERVER_NAME=aucr.local:5000
        TMP_FILE_FOLDER=/tmp/