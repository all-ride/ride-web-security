<?php

namespace pallo\application\cache\control;

use pallo\library\config\Config;
use pallo\library\security\model\SecurityModel;

use pallo\web\security\model\CachedSecurityModel;

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
     * @var pallo\library\security\model\SecurityModel
     */
    private $securityModel;

    /**
     * Instance of the configuration
     * @var pallo\library\config\Config
     */
    private $config;

    /**
     * Constructs a new security cache control
     * @param pallo\library\security\model\SecurityModel $securityModel
     * @param pallo\library\config\Config $config
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
        $model = $this->config->get('system.security.model.cache');
        if ($model) {
            return;
        }

        $model = $this->config->get('system.security.model.default');

        $this->config->set('system.security.model.cache', $model);
        $this->config->set('system.security.model.default', 'cache');
    }

    /**
     * Disables this cache
     * @return null
     */
    public function disable() {
        $model = $this->config->get('system.security.model.cache');

        $this->config->set('system.security.model.default', $model);
        $this->config->set('system.security.model.cache', null);
    }

    /**
     * Gets whether this cache is enabled
     * @return boolean
     */
    public function isEnabled() {
        return $this->securityModel instanceof CachedSecurityModel;
    }

    /**
     * Clears this cache
     * @return null
     */
    public function clear() {
        if (!$this->isEnabled()) {
            return;
        }

        $file = $this->securityModel->getFile();
        if ($file->exists()) {
            $file->delete();
        }
    }

}