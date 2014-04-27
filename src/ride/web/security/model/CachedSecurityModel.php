<?php

namespace ride\web\security\model;

use ride\library\security\model\Role;
use ride\library\security\model\SecurityModel;
use ride\library\security\model\User;
use ride\library\system\file\File;

/**
 * Implementation to cache an optimize an existing security model
 */
class CachedSecurityModel implements SecurityModel {

    /**
     * The cached ping result
     * @var boolean|null
     */
    private $ping;

    /**
     * The cached secured paths
     * @var array|null
     */
    private $securedPaths;

    /**
     * The cached permissions
     * @var array|null
     */
    private $permissions;

    /**
     * The cached roles
     * @var array|null
     */
    private $roles;

    /**
     * Constructs a new cached security model
     * @param SecurityModel $model The model to cache
     * @param \ride\library\system\file\File $file The file to cache to
     * @return null
     */
    public function __construct(SecurityModel $model, File $file) {
        $this->model = $model;
        $this->setFile($file);

        $this->ping = null;
        $this->securedPaths = null;
        $this->permissions = null;
        $this->roles = null;

        $this->readCache();
    }

    /**
     * Gets a string representation of this model
     * @return string
     */
    public function __toString() {
        if (method_exists($this->model, '__toString')) {
            $model = (string) $this->model;
        } else {
            $model = get_class($this->model);
        }

        return 'cache(' . $model . ')';
    }

    /**
     * Sets the file for the generated code
     * @param \ride\library\system\file\File $file The file to generate the code in
     * @return null
     */
    public function setFile(File $file) {
        $this->file = $file;
    }

    /**
	 * Gets the file for the generated code
     * @return \ride\library\system\file\File The file to generate the code in
     * @return null
     */
    public function getFile() {
        return $this->file;
    }

    /**
     * Checks if the security model is ready to work
     * @return boolean True if the model is ready, false otherwise
     */
    public function ping() {
        if ($this->ping !== null) {
            return $this->ping;
        }

        $this->ping = $this->model->ping();

        return $this->ping;
    }

    /**
     * Gets the paths which are secured for anonymous users
     * @return array Array with a path regular expression per element
     */
    public function getSecuredPaths() {
        if ($this->securedPaths !== null) {
            return $this->securedPaths;
        }

        $this->securedPaths = $this->model->getSecuredPaths();

        return $this->securedPaths;
    }

    /**
     * Sets the paths which are secured for anonymous users
     * @param array $routes Array with a path regular expression per element
     * @return null
     */
    public function setSecuredPaths(array $paths) {
        $this->model->setSecuredPaths($paths);

        $this->securedPaths = $paths;

        $this->clearCache();
    }

    /**
     * Creates a new user
     * @return User
     */
    public function createUser() {
        return $this->model->createUser();
    }

    /**
     * Gets a user by it's username
     * @param string $username Username of the user
     * @return User|null User object if found, null otherwise
     */
    public function getUserByUsername($username) {
        return $this->model->getUserByUsername($username);
    }

    /**
     * Gets a user by it's email address
     * @param string $email Email address of the user
     * @return User|null User object if found, null otherwise
     */
    public function getUserByEmail($email) {
        return $this->model->getUserByEmail($email);
    }

    /**
     * Find the users which match the provided part of a username
     * @param string $query Part of a username to match
     * @return array Array with the usernames which match the provided query
     */
    public function findUsersByUsername($query) {
        return $this->model->findUsersByUsername($query);
    }

    /**
     * Find the users which match the provided part of a email address
     * @param string $query Part of a email address
     * @return array Array with the usernames of the users which match the provided query
     */
    public function findUsersByEmail($query) {
        return $this->model->findUsersByEmail($query);
    }

    /**
     * Saves a user
     * @param User $user The user to save
     * @return null
     */
    public function saveUser(User $user) {
        $this->model->saveUser($user);
    }

    /**
     * Saves the provided roles for the provided user
     * @param User $user The user to update
     * @param array $roles The roles to set to the user
     * @return null
     */
    public function setRolesToUser(User $user, array $roles) {
        $this->model->setRolesToUser($user, $roles);
    }

    /**
     * Deletes the provided user
     * @param User $user The user to delete
     * @return null
     */
    public function deleteUser(User $user) {
        $this->model->deleteUser($user);
    }

    /**
     * Creates a new role
     * @return \ride\library\security\model\Role
     */
    public function createRole() {
        return $this->model->createRole();
    }

    /**
     * Gets a role by it's name
     * @param string $name Name of the role
     * @return Role|null Role object if found, null otherwise
     */
    public function getRoleByName($name) {
        return $this->model->getRoleByName($name);
    }

    /**
     * Gets all the roles
     * @return array
     */
    public function getRoles() {
        return $this->model->getRoles();
    }

    /**
     * Finds roles by it's name
     * @param string $query Part of the name
     * @return array Array with Role objects
     */
    public function findRolesByName($query) {
        return $this->model->findRolesByName($query);
    }

    /**
     * Saves a role
     * @param Role $role Role to save
     * @return null
     */
    public function saveRole(Role $role) {
        $this->model->saveRole($role);
    }

    /**
     * Sets the granted permissions to a role
     * @param Role $role Role to set the permissions to
     * @param array $permissionCodes Array with a permission code per element
     * @return null
     */
    public function setGrantedPermissionsToRole(Role $role, array $permissionCodes) {
        $this->model->setGrantedPermissionsToRole($role, $permissionCodes);
    }

    /**
     * Sets the allowed paths to a role
     * @param Role $role Role to set the routes to
     * @param array $paths Array with a path regular expression per element
     * @return null
     */
    public function setAllowedPathsToRole(Role $role, array $paths) {
        $this->model->setAllowedPathsToRole($role, $paths);
    }

    /**
     * Deletes the provided role
     * @param \ride\library\security\model\Role $role Role to delete
     * @return null
     */
    public function deleteRole(Role $role) {
        $this->model->deleteRole($role);
    }

    /**
     * Gets all the permissions
     * @return array Array with Permission objects
     */
    public function getPermissions() {
        if ($this->permissions !== null) {
            return $this->permissions;
        }

        $this->permissions = $this->model->getPermissions();

        return $this->permissions;
    }

    /**
     * Checks whether a given permission is available
     * @param string $code Code of the permission to check
     * @return boolean
     */
    public function hasPermission($code) {
        if ($this->permissions === null) {
            $this->getPermissions();
        }

        return isset($this->permissions[$code]);
    }

    /**
     * Registers a new permission to the model
     * @param string $code Code of the permission
     * @return null
     */
    public function registerPermission($code) {
        $this->model->registerPermission($code);

        $this->permissions = null;

        $this->clearCache();
    }

    /**
     * Unregisters an existing permission from the model
     * @param string $code Code of the permission
     * @return null
     */
    public function unregisterPermission($code) {
        $this->model->unregisterPermission($code);

        if (isset($this->permissions[$code])) {
            unset($this->permissions[$code]);
        }

        $this->clearCache();
    }

    /**
     * Deletes the generated cache file
     * @return null
     */
    protected function clearCache() {
        if ($this->file->exists()) {
            $this->file->delete();
        }
    }

    /**
     * Reads the generated cache file into memory
     * @return null
     */
    protected function readCache() {
        if (!$this->file->exists()) {
            $this->writeCache();
            return;
        }

        include $this->file->getPath();

        if (isset($ping)) {
            $this->ping = $ping;
        }

        if (isset($securedPaths)) {
            $this->securedPaths = $securedPaths;
        }

        if (isset($permissions)) {
            $this->permissions = $permissions;
        }
    }

    /**
     * Writes the current security model to the cache
     * @return null
     */
    protected function writeCache() {
        if (!$this->ping()) {
            // don't cache a model which is not ready
            return;
        }

        // make sure everything is set
        if ($this->securedPaths === null) {
            $this->securedPaths = $this->getSecuredPaths();
        }
        if ($this->permissions === null) {
            $this->permissions = $this->getPermissions();
        }

    	// generate the PHP code for this model
    	$php = $this->generatePhp();

    	// make sure the parent directory of the script exists
    	$parent = $this->file->getParent();
    	$parent->create();

    	// write the PHP code to file
    	$this->file->write($php);
    }

    /**
     * Generates a PHP source file for this security model
     * @return string
     */
    protected function generatePhp() {
        $output = "<?php\n\n";
        $output .= "/*\n";
        $output .= " * This file is generated by ride\web\security\model\CachedSecurityModel.\n";
        $output .= " */\n";
        $output .= "\n";
        $output .= '$ping = ' . var_export($this->ping, true) . ";\n";
        $output .= '$securedPaths = ' . var_export($this->securedPaths, true) . ";\n";
        $output .= '$permissions = ' . var_export($this->permissions, true) . ";\n";
        $output .= "\n";

        return $output;
    }

}
