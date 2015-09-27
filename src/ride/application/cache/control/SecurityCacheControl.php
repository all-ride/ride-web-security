<?php

namespace ride\application\cache\control;

use ride\library\config\Config;
use ride\library\security\model\SecurityModel;

use ride\web\security\model\CacheSecurityModel;

/**
 * Cache control implementation for the security model
 */
class SecurityCacheControl extends AbstractCacheControl {

    /**
     * Name of this control
     * @var string
     */
    const NAME = 'security';

    /**
     * Instance of the security model
     * @var \ride\library\security\model\SecurityModel
     */
    private $securityModel;

    /**
     * Instance of the configuration
     * @var \ride\library\config\Config
     */
    private $config;

    /**
     * Constructs a new security cache control
     * @param \ride\library\security\model\SecurityModel $securityModel
     * @param \ride\library\config\Config $config
     * @return null
     */
    public function __construct(SecurityModel $securityModel, Config $config) {
        $this->securityModel = $securityModel;
        $this->config = $config;
    }

    /**
     * Gets whether this cache can be enabled/disabled
     * @return boolean
     */
    public function canToggle() {
        return true;
    }

    /**
     * Enables this cache
     * @return null
     */
    public function enable() {
        $model = $this->config->get('system.security.model.default', 'chain');
        if ($model == 'cache') {
            return;
        }

        $this->config->set('system.security.model.cache', $model);
        $this->config->set('system.security.model.default', 'cache');
    }

    /**
     * Disables this cache
     * @return null
     */
    public function disable() {
        $model = $this->config->get('system.security.model.default', 'chain');
        if ($model != 'cache') {
            return;
        }

        $model = $this->config->get('system.security.model.cache');

        $this->config->set('system.security.model.default', $model);
        $this->config->set('system.security.model.cache', null);
    }

    /**
     * Gets whether this cache is enabled
     * @return boolean
     */
    public function isEnabled() {
        return $this->securityModel instanceof CacheSecurityModel;
    }

    /**
     * Warms this cache
     * @return null
     */
    public function warm() {
        if ($this->isEnabled()) {
            $this->securityModel->warmCache();
        }
    }

    /**
     * Clears this cache
     * @return null
     */
    public function clear() {
        if ($this->isEnabled()) {
            $this->securityModel->clearCache();
        }
    }

}
