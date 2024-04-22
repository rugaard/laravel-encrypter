![Banner](https://banners.beyondco.de/laravel-encrypter.png?theme=light&packageManager=npm+install&packageName=%40rugaard%2Flaravel-encryption&pattern=texture&style=style_1&description=Laravel+Encrypter+for+JavaScript&md=1&showWatermark=0&fontSize=100px&images=finger-print)
[![Release](https://github.com/rugaard/laravel-encrypter/actions/workflows/release.yaml/badge.svg)](https://github.com/rugaard/laravel-encrypter/actions/workflows/release.yaml)
[![License](https://img.shields.io/github/license/rugaard/laravel-encrypter?)](https://github.com/rugaard/laravel-encrypter/blob/main/LICENSE.md)

With this package you can encrypt/decrypt data between JavaScript and Laravel (PHP). It supports all the same ciphers algorithms as Laravel's Illuminate Encryption componenet.

## Installation

In your terminal, run the following command.

```shell
npm install --save @rugaard/laravel-encrypter
```

## Supported ciphers

The same AES-128 and AES-256 ciphers as in Laravel.

- `AES-128-CBC`
- `AES-256-CBC`
- `AES-128-GCM`
- `AES-256-GCM`
