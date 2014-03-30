Security is an important aspect of a website.
This library offers interfaces to secure and to lock off certain features of your application.

## Authorization

### Model

The security model offers a role-based access control.
A user can be part of multiple roles which each provide access to permissions and/or secured paths.

The implementation of the security model is not done by the library but left open for the application.
A basic implementation is provided by the _ride-web-wecurity-generic_ module.

### Paths

You can secure paths by defining them in the security manager.
All secured paths set in the security manager are denied by default.
A user can obtain access to a secured path through a role.

#### Path Regular Expression

All paths, secured or allowed, are declared with a basic regular expression.
A * is used as a wildcard for a single path token, ** for everything.

Some examples:

    /admin/**
    /product/*/internal
    /product/25

### Permissions

Permissions are defined by a _._ separated string.
The security model can provide a description for a permission.

In PHP, permissions are checked on the security manager:

    <?php

    use ride\library\security\SecurityManager;

    function foo(SecurityManager $securityManager) {
        if (!$securityManager->isPermissionGranted('test.permission')) {
            return false;
        }

        // some logic

        return true;
    }

There is no need to define the permissions in the model.
They will automatically be defined when a permission is checked for access.

### HTTP Authentication

Define the following dependencies to enable HTTP authentication:

    {
        "dependencies": [
            {
                "interfaces": "ride\\library\\security\\authenticator\\Authenticator",
                "class": "ride\\web\\security\\authenticator\\HttpAuthenticator",
                "id": "http",
                "calls": [
                    {
                        "method": "__construct",
                        "arguments": [
                            {
                                "name": "io",
                                "type": "dependency",
                                "properties": {
                                    "interface": "ride\\library\\security\\authenticator\\io\\AuthenticatorIO",
                                    "id": "security"
                                }
                            },
                            {
                                "name": "realm",
                                "type": "parameter",
                                "properties": {
                                    "key": "security.realm"
                                }
                            },
                            {
                                "name": "eventManager",
                                "type": "dependency",
                                "properties": {
                                    "interface": "ride\\library\\event\\EventManager"
                                }
                            }
                        ]
                    }
                ]
            },
            {
                "interfaces": "ride\\library\\security\\authenticator\\Authenticator",
                "extends": "chain",
                "id": "chain",
                "calls": [
                    {
                        "method": "addAuthenticator",
                        "arguments": [
                            {
                                "name": "authenticator",
                                "type": "dependency",
                                "properties": {
                                    "interface": "ride\\library\\security\\authenticator\\Authenticator",
                                    "id": "http"
                                }
                            }
                        ]
                    }
                ]
            },
        ]
    }
