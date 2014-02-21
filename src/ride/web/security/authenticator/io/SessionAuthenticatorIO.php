<?php

namespace ride\web\security\authenticator\io;

use ride\library\http\Request;
use ride\library\security\authenticator\io\AuthenticatorIO;

/**
 * Session input/output implementation for the authenticator
 */
class SessionAuthenticatorIO implements AuthenticatorIO {

    /**
     * Instance of the request
     * @var ride\library\http\Request
     */
    protected $request;

    /**
     * Sets the request to this IO
     * @param ride\library\http\Request
     * @return null
     */
    public function setRequest(Request $request = null) {
        $this->request = $request;
    }

    /**
     * Sets a value to the storage
     * @param string $key The key of the value
     * @param string $value The value
     * @return null
     */
    public function set($key, $value) {
        if (!$this->request) {
            throw new SecurityException('Could not store the authentication value: no request set to retrieve the session from');
        }

        $session = $this->request->getSession();

        if ($session) {
            $session->set($key, $value);
        }
    }

    /**
     * Gets a value from the storage
     * @param string $key The key of the value
     * @param string|null The value if set, null otherwise
     */
    public function get($key) {
        if (!$this->request || !$this->request->hasSession()) {
            return null;
        }

        return $this->request->getSession()->get($key);
    }

}