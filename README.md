# Ride: Web Security

This module implements the security layer for a Ride web application.

## Parameters

* __security.hash__: Name of the password hash algorithm, eg. sha1, md5, ...
* __security.unique__: Flag to force unique sessions which forbids a user to login with multiple clients.
* __security.voter.strategy__: Set the strategy of the voter chain: affirmative, consensus or unanimous
* __system.security.model.default__: Dependency id of the default security model
* __system.security.model.cache__: Dependency id of the cached security model
* __system.cache.security__: Path to the PHP file of the security layer's cache implementation.

## Events

* __security.password.update__: Invoked before saving a user when the password has changed. This event passes the user instance and the plain text password as argument.
* __security.authentication.login__: Invoked after the user has been authenticated with username and password. This event passes the user instance as argument.

## Related Modules 

- [ride/app](https://github.com/all-ride/ride-app)
- [ride/cli-security](https://github.com/all-ride/ride-cli-security)
- [ride/lib-security](https://github.com/all-ride/ride-lib-security)
- [ride/lib-security-generic](https://github.com/all-ride/ride-lib-security-generic)
- [ride/lib-security-oauth](https://github.com/all-ride/ride-lib-security-oauth)
- [ride/web](https://github.com/all-ride/ride-web)
- [ride/web-security-generic](https://github.com/all-ride/ride-web-security-generic)
- [ride/web-security-oauth](https://github.com/all-ride/ride-web-security-oauth)
- [ride/web-security-orm](https://github.com/all-ride/ride-web-security-orm)

## Installation

You can use [Composer](http://getcomposer.org) to install this application.

```
composer require ride/web-security
```
