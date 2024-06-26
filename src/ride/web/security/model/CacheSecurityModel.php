<?php

namespace ride\web\security\model;

use ride\library\security\model\Role;
use ride\library\security\model\SecurityModel;
use ride\library\security\model\User;
use ride\library\system\file\File;

/**
 * Implementation to cache an optimize an existing security model
 */
class CacheSecurityModel implements SecurityModel {

    private $model;

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

    private $file;

    /**
     * @var true
     */
    private $needsWrite;

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
     * Destructs the cached security model
     * @return null
     */
    public function __destruct() {
        if (isset($this->needWrite)) {
            $this->warmCache();
        }
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
     * Saves the provided roles for the provided user
     * @param User $user The user to update
     * @param array $roles The roles to set to the user
     * @return null
     */
    public function setRolesToUser(User $user, array $roles) {
        $this->model->setRolesToUser($user, $roles);
    }

    /**
     * Gets a user by it's id
     * @param string $id Id of the user
     * @return User|null User object if found, null otherwise
     */
    public function getUserById($id) {
        return $this->model->getUserById($id);
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
     * Gets the users
     * @param array $options Options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     *     <li>username</li>
     *     <li>email</li>
     *     <li>page</li>
     *     <li>limit</li>
     * </ul>
     * @return array
     */
    public function getUsers(array $options = null) {
        return $this->model->getUsers($options);
    }

    /**
     * Counts the users
     * @param array $options Extra options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     *     <li>username</li>
     *     <li>email</li>
     * </ul>
     * @return integer
     */
    public function countUsers(array $options = null) {
        return $this->model->countUsers($options);
    }

    /**
     * Creates a new user
     * @return User
     */
    public function createUser() {
        return $this->model->createUser();
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
     * Deletes the provided user
     * @param User $user The user to delete
     * @return null
     */
    public function deleteUser(User $user) {
        $this->model->deleteUser($user);
    }

    /**
     * Gets a role by it's id
     * @param string $id Id of the role
     * @return Role|null Role object if found, null otherwise
     */
    public function getRoleById($id) {
        return $this->model->getRoleById($id);
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
     * @param array $options Options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     *     <li>page</li>
     *     <li>limit</li>
     * </ul>
     * @return array
     */
    public function getRoles(array $options = null) {
        return $this->model->getRoles($options);
    }

    /**
     * Counts the roles
     * @param array $options Extra options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     * </ul>
     * @return integer
     */
    public function countRoles(array $options = null) {
        return $this->model->countRoles($options);
    }

    /**
     * Creates a new role
     * @return \ride\library\security\model\Role
     */
    public function createRole() {
        return $this->model->createRole();
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
    public function addPermission($code) {
        $this->model->addPermission($code);

        $this->permissions = null;

        $this->clearCache();
    }

    /**
     * Unregisters an existing permission from the model
     * @param string $code Code of the permission
     * @return null
     */
    public function deletePermission($code) {
        $this->model->deletePermission($code);

        if (isset($this->permissions[$code])) {
            unset($this->permissions[$code]);
        }

        $this->clearCache();
    }

    /**
     * Reads the generated cache file into memory
     * @return null
     */
    protected function readCache() {
        if (!$this->file->exists()) {
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
     * Warms up the cache
     * @return null 
     */
    public function warmCache() {
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
     * Deletes the generated cache file
     * @return null
     */
    public function clearCache() {
        if ($this->file->exists()) {
            $this->file->delete();
        }

        $this->needsWrite = true;
    }

    /**
     * Generates a PHP source file for this security model
     * @return string
     */
    protected function generatePhp() {
        $output = "<?php\n\n";
        $output .= "/*\n";
        $output .= " * This file is generated by ride\web\security\model\CacheSecurityModel.\n";
        $output .= " */\n";
        $output .= "\n";
        $output .= '$ping = ' . var_export($this->ping, true) . ";\n";
        $output .= '$securedPaths = ' . var_export($this->securedPaths, true) . ";\n";

        if ($this->permissions) {
            $output .= '$permissions = null;' . "\n";
        } else {
            $output .= '$permissions = array();' . "\n";
        }

        $output .= "\n";

        return $output;
    }

}
