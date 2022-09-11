# unzoner-dashboard
> [black.box Unzoner](https://www.unzoner.com/#technical-architecture) dashboard service using Flask/Blueprint on Python

This block implements black.box Unzoner dashboard backend, which provides a bootstrap
WebUI to help customers operate their black.box devices.


## usage
* add the latest [unzoner-dashboard](https://hub.balena.io/organizations/belodetek/blocks) block to your balenaCloud fleet composition (e.g. `amd64`)

```yml
version: '2.4'

services:
  unzoner-api:
    ...

  unzoner-dashboard:
    # https://www.balena.io/docs/learn/develop/blocks/#using-your-block-in-other-projects
    image: bh.cr/belodetek/unzoner-dashboard-amd64
    restart: unless-stopped
    ports:
      # it is assumed there is a load-baancer/proxy fronting the API
      - "80:80/tcp"
    # https://www.balena.io/docs/reference/supervisor/docker-compose/#labels
    labels:
      io.balena.update.strategy: download-then-kill
```

## configuration
> see [config.py](src/app/config.py) to set fleet environment variables

name | description | example
--- | --- | ---
API_HOST | your Unzoner API URL | (e.g.) `https://api.acme.com`
API_SECRET | shared secret | (e.g.) `openssl rand -hex 16`
API_VERSION | your Unzoner API version | (e.g.) `1.0`
SMTP_FROM | Your Gmail email address | (e.g) `team@acme.com`
SMTP_PASSWORD | Google app password | [link](https://support.google.com/accounts/answer/185833?hl=en)
SMTP_RCPT_TO | Your Gmail email address | (e.g) `team@acme.com`
SMTP_USERNAME | Your Gmail email address | (e.g) `team@acme.com`
