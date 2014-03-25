<?php

namespace ride\web\security;

use ride\library\event\Event;
use ride\library\http\Header;
use ride\library\http\Response;
use ride\library\security\authenticator\ChainedAuthenticator;
use ride\library\security\exception\UnauthorizedException;
use ride\library\security\SecurityManager;

use ride\web\security\authenticator\HttpAuthenticator;

/**
 * Application listener to integrate security
 */
class ApplicationListener {

    /**
     * Checks if the current route is allowed.
     * @param ride\library\event\Event $event
     * @param ride\library\security\SecurityManager $securityManager
     * @return null
     * @throws ride\library\security\exception\UnauthorizedException when the
     * route is not allowed
     */
    public function protectSecuredPaths(Event $event, SecurityManager $securityManager) {
        $web = $event->getArgument('web');
        $request = $web->getRequest();
        if (!$request) {
            return;
        }

        $path = $request->getBasePath(true);

        if ($securityManager->isPathAllowed($path)) {
            return;
        }

        throw new UnauthorizedException();
    }

    /**
     * Act on a uncaught exception
     * @param ride\library\event\Event $event
     * @param ride\library\security\SecurityManager $securityManager
     * @return null
     */
    public function handleException(Event $event, SecurityManager $securityManager) {
        $exception = $event->getArgument('exception');
        if (!$exception instanceof UnauthorizedException) {
            return;
        }

        $web = $event->getArgument('web');
        $response = $web->getResponse();

        $user = $securityManager->getUser();
        $authenticator = $securityManager->getAuthenticator();
        $httpAuthenticator = $this->getHttpAuthenticator($authenticator);

        if (!$user && $httpAuthenticator) {
            $response->addHeader(Header::HEADER_AUTHENTICATE, $httpAuthenticator->getAuthenticateHeaderValue());
            $response->setStatusCode(Response::STATUS_CODE_UNAUTHORIZED);
        } else {
            $response->setStatusCode(Response::STATUS_CODE_FORBIDDEN);
        }
    }

    /**
     * Checks if a HTTP authenticator is active
     * @param ride\library\security\authenticator\Authenticator $authenticator
     * @return boolean
     */
    protected function getHttpAuthenticator($authenticator) {
        if ($authenticator instanceof HttpAuthenticator) {
            return $authenticator;
        }

        if ($authenticator instanceof ChainedAuthenticator) {
            $authenticators = $authenticator->getAuthenticators();
            foreach ($authenticators as $authenticator) {
                if ($authenticator instanceof HttpAuthenticator) {
                    return $authenticator;
                }
            }
        }

        return false;
    }

}
