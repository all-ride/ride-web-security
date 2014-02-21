<?php

namespace ride\security\authenticator;

use ride\library\event\EventManager;
use ride\library\event\Event;
use ride\library\http\Request;
use ride\library\security\authenticator\io\AuthenticatorIO;
use ride\library\security\authenticator\AbstractAuthenticator;
use ride\library\security\authenticator\Authenticator;
use ride\library\security\exception\SecurityException;
use ride\library\security\model\User;
use ride\library\security\SecurityManager;

/**
 * Simple HTTP digest authenticator to wrap around another authenticator
 *
 * Users which are stored before using this authenticator will not be able to
 * authenticate themselves. This is due to hashed passwords of the security
 * model.
 *
 * This authenticator hooks into the security model and stores the A1 part of
 * the valid digest response as a preference of the user. If the preference is
 * not there, or the realm has changed, authentication will fail
 *
 * @see http://www.faqs.org/rfcs/rfc2617
 */
class HttpAuthenticator extends AbstractAuthenticator {

    /**
     * Name of the user preference for the A1 digest
     * @var string
    */
    const PREFERENCE_A1 = 'security.digest.a1';

    /**
     * Basic authentication type
     * @var string
     */
    const TYPE_BASIC = 'basic';

    /**
     * Digest authentication type
     * @var string
     */
    const TYPE_DIGEST = 'digest';

    /**
     * The name of the variable to store the nonce
     * @var string
     */
    const VAR_NONCE = 'security.nonce';

    /**
     * The realm for the authentication
     * @var string
     */
    private $realm;

    /**
     * The nonce of the authentication
     * @var string
     */
    private $nonce;

    /**
     * Type of the authentication (basic or digest)
     * @var string
     */
    private $type;

    /**
     * Constructs a new authenticator
     * @param ride\core\Zibo $ride Instance of Zibo
     * @param ride\library\security\authenticator\io\AuthenticatorIO $io
     * @param string $realm The realm for the authentication
     * @return null
     */
    public function __construct(AuthenticatorIO $io, $realm, EventManager $eventManager = null) {
        $this->io = $io;
        $this->user = false;
        $this->realm = $realm;
        $this->type = self::TYPE_DIGEST;

        $this->initNonce();

        if ($eventManager) {
            $eventManager->addEventListener(SecurityManager::EVENT_PASSWORD_UPDATE, array($this, 'updateDigest'));
        }
    }

    /**
     * Sets the type of HTTP authentication
     * @param string $type
     * @return null
     * @throws Exception when an invalid type has been probided
     */
    public function setType($type) {
        if ($type != self::TYPE_BASIC && $type != self::TYPE_DIGEST) {
            throw new SecurityException('Provided type is invalid, try ' . self::TYPE_BASIC . ' or ' . self::TYPE_DIGEST);
        }

        $this->type = $type;
    }

    /**
     * Hook with the security model used to store A1 of the
     * @param ride\library\event\Event $event
     * @return null
     */
    public function updateDigest(Event $event) {
        $user = $event->getArgument('user');
        $password = $event->getArgument('password');

        $username = $user->getUserName();
        $a1 = md5($username . ':' . $this->realm . ':' . $password);

        $user->setUserPreference(self::PREFERENCE_A1, $a1);
    }

    /**
     * Logout the current user
     * @return null
     */
    public function logout() {
        $this->user = false;

        $this->refreshNonce();
    }

    /**
     * Gets the current user.
     * @return ride\library\security\model\User User instance if a user is
     * logged in, null otherwise
     */
    public function getUser() {
        if ($this->user !== false) {
            return $this->user;
        }

        return null;
    }

    /**
     * Authenticates a user through the incoming request
     * @param ride\library\http\Request $request
     * @return ride\library\security\model\User|null User if the authentication
     * succeeded
     */
    public function authenticate(Request $request) {
        if (isset($_SERVER['PHP_AUTH_DIGEST'])) {
            return $this->authenticateDigest($request);
        } else {
            return $this->authenticateBasic($request);
        }
    }

    /**
     * Authenticates a user through the incoming request with the basic method
     * @param ride\library\http\Request $request
     * @return ride\library\security\model\User|null User if the authentication
     * succeeded
     */
    protected function authenticateBasic($request) {
        if (!(isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW']))) {
            return null;
        }

        $this->user = $this->securityManager->getAuthenticator()->login($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);

        return $this->user;
    }

    /**
     * Authenticates a user through the incoming request with the digest method
     * @param ride\library\http\Request $request
     * @return ride\library\security\model\User|null User if the authentication
     * succeeded
     */
    protected function authenticateDigest(Request $request) {
        $digest = $this->parseDigest($_SERVER['PHP_AUTH_DIGEST']);
        if (!$digest) {
            return null;
        }

        $securityModel = $this->securityManager->getSecurityModel();

        $user = $securityModel->getUserByUsername($digest['username']);
        if ($user) {
            $validResponse = $this->generateValidResponse($user, $digest, $request->getMethod());

            if ($digest['response'] == $validResponse) {
                if (!$user || ($user && !$user->isUserActive())) {
                    $this->user = null;
                } else {
                    $this->user = $this->setUser($user);
                }
            } else {
                $this->user = null;
            }
        } else {
            $this->user = null;
        }

        return $this->user;
    }

    /**
     * Sets the current authenticated user
     * @param ride\library\security\model\User $user User to set the
     * authentication for
     * @return ride\library\security\model\User updated user with the
     * information of the authentification
     */
    public function setUser(User $user) {
        return $this->user = $user;
    }

    /**
     * Generates a valid response from the digest data
     * @param ride\library\security\model\User $user
     * @param array $digest The data of the digest
     * @param string $method HTTP method
     * @return string Valid response to compare the digest response with
     */
    private function generateValidResponse(User $user, array $digest, $method) {
        $a1 = $user->getUserPreference(self::PREFERENCE_A1);
        if (!$a1) {
            return null;
        }

        $a2 = md5($method . ':' . $digest['uri']);

        return md5($a1 . ':' . $this->nonce . ':' . $digest['nc'] . ':' . $digest['cnonce'] . ':' . $digest['qop'] . ':' . $a2);
    }

    /**
     * Parses the provided string digest into an array of key-value pairs
     * @param string $digest The digest string to parse
     * @return array Array with key-value pairs
     */
    private function parseDigest($digest) {
        // protect against missing data
        $neededParts = array(
            'nonce' => 1,
            'nc' => 1,
            'cnonce' => 1,
            'qop' => 1,
            'username' => 1,
            'uri' => 1,
            'response' => 1,
            'realm' => 1,
            'opaque' => 1,
        );
        $data = array();
        $keys = implode('|', array_keys($neededParts));

        preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $digest, $matches, PREG_SET_ORDER);

        foreach ($matches as $match) {
            $data[$match[1]] = $match[3] ? $match[3] : $match[4];
            unset($neededParts[$match[1]]);
        }

        return $neededParts ? false : $data;
    }

    /**
     * Gets the value for the WWW-Authenticate header
     * @return string
     */
    public function getAuthenticateHeaderValue() {
        if ($this->type == self::TYPE_DIGEST) {
            $header = 'Digest realm="' . $this->realm . '"';
            $header .= ',qop="auth"';
            $header .= ',nonce="' . $this->nonce . '"';
            $header .= ',opaque="' . md5($this->realm) . '"';
        } else {
            $header = 'Basic realm="' . $this->realm . '"';
        }

        return $header;
    }

    /**
     * Initializes the nonce
     * @return null
     */
    private function initNonce() {
        $this->nonce = $this->io->get(self::VAR_NONCE);
        if (!$this->nonce) {
            $this->refreshNonce();
        }
    }

    /**
     * Creates a new nounce
     * @return null
     */
    private function refreshNonce() {
        $this->nonce = uniqid();
        $this->io->set(self::VAR_NONCE, $this->nonce);
    }

}