<?php

namespace ride\web\security;

use ride\library\security\SecurityManager as LibSecurityManager;

class SecurityManager extends LibSecurityManager {

    /**
     * Checks whether the current user is allowed to view the provided URL
     * @param string $url URL to check
     * @return boolean
     */
    public function isUrlAllowed($url) {
        if (!$this->request) {
            return parent::isUrlAllowed();
        }

        $baseUrl = $this->request->getBaseUrl();
        $path = str_replace($baseUrl, '', $url);

        if (strpos($path, '?') !== false) {
            list($path, $query) = explode('?', $path, 2);
        }

        return $this->isPathAllowed($path, $this->request->getMethod());
    }

}
