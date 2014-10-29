<?php
/**
 * DokuWiki Plugin for Magento (Auth Component)
 *
 * See the configuration. There are settings for customers, groups, administrators, and roles.
 *
 * Notes:
 * - Magento customer data is retrieved only when necessary, and cached in memory.
 * - Magento administrator data is retrieved only when necessary, and cached in memory.
 * - Password hashes are retrieved, but never stored in memory.
 *
 * @license GPL v3 http://www.gnu.org
 * @author  Z3 Development <z3-dev@gfnews.net>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class auth_plugin_magento extends DokuWiki_Auth_Plugin {
    /** @var array user data for indentifying logins */
    protected $users  = null;
    /** @var array administrator data for indentifying logins */
    protected $admins = null;
    /** @var array roles for provisioning administrators */
    protected $roles  = null;

    protected $db_dsn    = null;
    protected $db_user   = null;
    protected $db_passwd = null;

    /**
     * Constructor.
     */
    public function __construct() {
        parent::__construct(); // for compatibility

        $this->cando['addUser']     = false; // can Users be created?
        $this->cando['delUser']     = false; // can Users be deleted?
        $this->cando['modLogin']    = false; // can login names be changed?
        $this->cando['modPass']     = false; // can passwords be changed?
        $this->cando['modName']     = false; // can real names be changed?
        $this->cando['modMail']     = false; // can emails be changed?
        $this->cando['modGroups']   = false; // can groups be changed?
        $this->cando['getUsers']    = false; // can a (filtered) list of users be retrieved?
        $this->cando['getUserCount']= false; // can the number of users be retrieved?
        $this->cando['getGroups']   = false; // can a list of available groups be retrieved?
        $this->cando['external']    = false; // does the module do external auth checking?
        $this->cando['logout']      = true;  // can the user logout again? (eg. not possible with HTTP auth)

        
        $this->db_dsn    = $this->getConf( 'databaseDSN' );
        $this->db_user   = $this->getConf( 'databaseUser' );
        $this->db_passwd = $this->getConf( 'databasePassword' );

        // set success to true, and let DokuWiki take over
        $this->success = true;
    }


    /**
     * Log off the current user [ OPTIONAL ]
     */
    //public function logOff() {
    //}

    /**
     * Do all authentication [ OPTIONAL ]
     *
     * @param   string  $user    Username
     * @param   string  $pass    Cleartext Password
     * @param   bool    $sticky  Cookie should not expire
     * @return  bool             true on successful auth
     */
    //public function trustExternal($user, $pass, $sticky = false) {
    //}

    /**
     * Check user+password
     *
     * May be ommited if trustExternal is used.
     *
     * @param   string $user the user name
     * @param   string $pass the clear text password
     * @return  bool true if verified
     */
    public function checkPass($user, $pass) {
        $entity = $this->_findUser( $user );
        if ( $entity > 0 ) {
            return $this->_checkUserPassword( $entity, $pass );
        }
        $entity = $this->_findAdmin( $user );
        if ( $entity > 0 ) {
            return $this->_checkAdminPassword( $entity, $pass );
        }
        return false;
    }

    /**
     * Return user info
     *
     * Returns info about the given user needs to contain
     * at least these fields:
     *
     * name string  full name of the user
     * mail string  email address of the user
     * grps array   list of groups the user is in
     *
     * @param   string $user the user name
     * @return  array containing user data or false
     */
    public function getUserData($user) {
        global $conf;

        $entity = $this->_findUser( $user );
        if ( $entity > 0 ) {
            $name = "{$this->users[$entity]['first']} {$this->users[$entity]['last']}";

            if ( ! isset( $this->users[$entity]['mail']) ) $this->_loadMailAddress( $entity );

            if ( ! isset( $this->users[$entity]['groups']) ) $this->_loadUserGroups( $entity );

        // add magento groups
            $groups = $this->users[$entity]['groups'];
        // add default group (if configured)
            if ( $this->getConf( 'includeDefaultGroup' ) == 1 ) {
                array_push( $groups, $conf[ 'defaultgroup' ] );
            }
        // add additional groups (if configured)
            if ( $this->getConf( 'userGroups' ) ) {
                $usergroups = array_values( array_filter( explode( ",", $this->getConf( 'userGroups' ) ) ) );
                $groups = array_merge( $groups, $usergroups );
            }

            $data = array();
            $data['name'] = $name;
            $data['mail'] = $this->users[$entity]['mail'];
            $data['grps'] = $groups;
            return $data;
        }
        $entity = $this->_findAdmin( $user );
        if ( $entity > 0 ) {
            if ( ! isset( $this->admins[$entity]['roles']) ) $this->_loadAdminRoles( $entity );

        // add magento roles
            $groups = $this->admins[$entity]['roles'];
        // add default group (if configured)
            if ( $this->getConf( 'includeDefaultGroup' ) == 1 ) {
                array_push( $groups, $conf[ 'defaultgroup' ] );
            }
        // add additional groups (if configured)
            if ( $this->getConf( 'adminGroups' ) ) {
                $usergroups = array_values( array_filter( explode( ",", $this->getConf( 'adminGroups' ) ) ) );
                $groups = array_merge( $groups, $usergroups );
            }

            $data = array();
            $data['name'] = "{$this->admins[$entity]['first']} {$this->admins[$entity]['last']}";
            $data['mail'] = $this->admins[$entity]['mail'];
            $data['grps'] = $groups;
            return $data;
        }
        return false;
    }

    /**
     * Create a new User [implement only where required/possible]
     *
     * Returns false if the user already exists, null when an error
     * occurred and true if everything went well.
     *
     * The new user HAS TO be added to the default group by this
     * function!
     *
     * Set addUser capability when implemented
     *
     * @param  string     $user
     * @param  string     $pass
     * @param  string     $name
     * @param  string     $mail
     * @param  null|array $grps
     * @return bool|null
     */
    //public function createUser($user, $pass, $name, $mail, $grps = null) {
    //}

    /**
     * Modify user data [implement only where required/possible]
     *
     * Set the mod* capabilities according to the implemented features
     *
     * @param   string $user    nick of the user to be changed
     * @param   array  $changes array of field/value pairs to be changed (password will be clear text)
     * @return  bool
     */
    //public function modifyUser($user, $changes) {
    //}

    /**
     * Delete one or more users [implement only where required/possible]
     *
     * Set delUser capability when implemented
     *
     * @param   array  $users
     * @return  int    number of users deleted
     */
    //public function deleteUsers($users) {
    //}

    /**
     * Bulk retrieval of user data [implement only where required/possible]
     *
     * Set getUsers capability when implemented
     *
     * @param   int   $start     index of first user to be returned
     * @param   int   $limit     max number of users to be returned
     * @param   array $filter    array of field/pattern pairs, null for no filter
     * @return  array list of userinfo (refer getUserData for internal userinfo details)
     */
    //public function retrieveUsers($start = 0, $limit = -1, $filter = null) {
    //}

    /**
     * Return a count of the number of user which meet $filter criteria
     * [should be implemented whenever retrieveUsers is implemented]
     *
     * Set getUserCount capability when implemented
     *
     * @param  array $filter array of field/pattern pairs, empty array for no filter
     * @return int
     */
    //public function getUserCount($filter = array()) {
    //}

    /**
     * Define a group [implement only where required/possible]
     *
     * Set addGroup capability when implemented
     *
     * @param   string $group
     * @return  bool
     */
    //public function addGroup($group) {
    //}

    /**
     * Retrieve groups [implement only where required/possible]
     *
     * Set getGroups capability when implemented
     *
     * @param   int $start
     * @param   int $limit
     * @return  array
     */
    //public function retrieveGroups($start = 0, $limit = 0) {
    //    return array();
    //}

    /**
     * Return case sensitivity of the backend
     *
     * When your backend is caseinsensitive (eg. you can login with USER and
     * user) then you need to overwrite this method and return false
     *
     * @return bool
     */
    public function isCaseSensitive() {
    // NOTE: Magento administrators login with "user name" which is case sensitive.
        return true;
    }

    /**
     * Sanitize a given username
     *
     * This function is applied to any user name that is given to
     * the backend and should also be applied to any user name within
     * the backend before returning it somewhere.
     *
     * This should be used to enforce username restrictions.
     *
     * @param string $user username
     * @return string the cleaned username
     */
    public function cleanUser( $user ) {
        return cleanID( str_replace( ':', $this->getConf['sepchar'], $user ) );
    }

    /**
     * Sanitize a given groupname
     *
     * This function is applied to any groupname that is given to
     * the backend and should also be applied to any groupname within
     * the backend before returning it somewhere.
     *
     * This should be used to enforce groupname restrictions.
     *
     * Groupnames are to be passed without a leading '@' here.
     *
     * @param  string $group groupname
     * @return string the cleaned groupname
     */
    public function cleanGroup( $group ) {
        return cleanID( str_replace(':', $this->getConf['sepchar'], $group ) );
    }

    /**
     * Check Session Cache validity [implement only where required/possible]
     *
     * DokuWiki caches user info in the user's session for the timespan defined
     * in $conf['auth_security_timeout'].
     *
     * This makes sure slow authentication backends do not slow down DokuWiki.
     * This also means that changes to the user database will not be reflected
     * on currently logged in users.
     *
     * To accommodate for this, the user manager plugin will touch a reference
     * file whenever a change is submitted. This function compares the filetime
     * of this reference file with the time stored in the session.
     *
     * This reference file mechanism does not reflect changes done directly in
     * the backend's database through other means than the user manager plugin.
     *
     * Fast backends might want to return always false, to force rechecks on
     * each page load. Others might want to use their own checking here. If
     * unsure, do not override.
     *
     * @param  string $user - The username
     * @return bool
     */
    //public function useSessionCache($user) {
    //}

/*
 * Implementation specific functions.
 */
    /**
     * Find user entity from the user data
     *
     * Magento (default) requires both first and last names
     *
     * The given user is matched against the first and last names of Magento in either order
     * All spaces in names are converted to the seperator character
     *
     * @param   string $user the user name
     * @return  int          the entity found in the list of users or -1
     */
    protected function _findUser( $user ) {
    // load the user data if not already
        if( $this->users === null ) $this->_loadUserData();

        $sep = $this->getConf['sepchar'];
    // find the given user in the user data
        $count = 0;
        $entity = 0;
        foreach( $this->users as $entry ) {
            $first_last = "{$entry['first']} {$entry['last']}";
            $first_last = cleanID( $first_last );
            $last_first = "{$entry['last']} {$entry['first']}";
            $last_first = cleanID( $last_first );
            if ( strnatcasecmp ( $user , $first_last ) === 0 ) {
                $entity = $entry['entity'];
                $count = $count + 1;
            }
            if ( strnatcasecmp ( $user , $last_first ) === 0 ) {
                $entity = $entry['entity'];
                $count = $count + 1;
            }
        }
        if ( $count == 1 ) return $entity;
        if ( $count > 1 ) msg( "Your user name is ambiguous. Please change your account information via the store.", -1);
        return -1;
    }

    /**
     * Check the given password for the given entity (customer) against Magento
     *
     * The check is performed by comparing hashes
     *
     * @param   int    $entity the entity of the user
     * @param   string $pass   the clear text password
     */
    protected function _checkUserPassword( $entity, $pass ) {
        try {
        // get a connection to the database
            $dbh = new PDO( $this->db_dsn, $this->db_user, $this->db_passwd, array( PDO::ATTR_PERSISTENT => true ) );
            $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // query the password hash
            $sql = "select a.entity_id entity, a.value hash from customer_entity_varchar a where a.attribute_id = 12 and a.entity_id = {$entity};";
            $hash = "";
            foreach( $dbh->query( $sql ) as $row ) {
                if ( $entity === $row['entity'] ) {
                    $hash = $row['hash'];
                }
            }
            $dbh = null;
        // compare in the same way as Magento
            return $this->validateHash( $pass, $hash );
        } catch (PDOException $e) {
            if ( $this->getConf( 'debugDatabase' ) == 1 ) {
                msg( $e->getMessage(), -1);
            }
        }
        return false;
    }

    /**
     * Find administrator entity from the administrator data
     *
     * The given user is matched against the "user" found in the Magento database
     * All spaces in names are converted to the seperator character
     *
     * @param   string $user the user name
     * @return  int          the entity found in the list of administrators or -1
     */
    protected function _findAdmin( $user ) {
    // load the administrator data if not already
        if( $this->admins === null ) $this->_loadAdminData();
    // find the given administrator in the admin data
        foreach( $this->admins as $entry ) {
            $user_id = $entry['user'];
            $user_id = cleanID( $user_id );
            if ( strnatcasecmp ( $user , $user_id ) === 0 ) return $entry['entity'];
        }
        return -1;
    }

    /**
     * Check the given password for the given entity (administrator) against Magento
     *
     * The check is performed by comparing hashes
     *
     * @param   int    $entity the entity of the user
     * @param   string $pass   the clear text password
     */
    protected function _checkAdminPassword( $entity, $pass ) {
        try {
        // get a connection to the database
            $dbh = new PDO( $this->db_dsn, $this->db_user, $this->db_passwd, array( PDO::ATTR_PERSISTENT => true ) );
            $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // query the password hash
            $sql = "select user_id entity,password hash from admin_user where user_id = {$entity};";
            $hash = "";
            foreach( $dbh->query( $sql ) as $row ) {
                if ( $entity === $row['entity'] ) {
                    $hash = $row['hash'];
                }
            }
            $dbh = null;
        // compare in the same way as Magento
            return $this->validateHash( $pass, $hash );
        } catch (PDOException $e) {
            if ( $this->getConf( 'debugDatabase' ) == 1 ) {
                msg( $e->getMessage(), -1);
            }
        }
        return false;
    }

// TAKE FROM MAGENTO SOURCE CODE 1.8.1
    /**
     * Hash a string
     *
     * @param string $data
     * @return string
     */
    protected function hash($data)
    {
        return md5($data);
    }

    /**
     * Validate hash against hashing method (with or without salt)
     *
     * @param string $password
     * @param string $hash
     * @return bool
     */
    protected function validateHash($password, $hash)
    {
        $hashArr = explode(':', $hash);
        switch (count($hashArr)) {
            case 1:
                return $this->hash($password) === $hash;
            case 2:
                return $this->hash($hashArr[1] . $password) === $hashArr[0];
        }
        return false;
    }
// TAKE FROM MAGENTO SOURCE CODE 1.8.1

    /**
     * Load all user (customer) data from Magento, i.e. just the information require to identify the user
     *
     * @return bool
     */
    protected function _loadUserData() {
        $this->users = array();
        // query only if configured
        if ( $this->getConf( 'includeCustomers' ) != 1 ) return true;

        try {
        // get a connection to the database
            $dbh = new PDO( $this->db_dsn, $this->db_user, $this->db_passwd, array( PDO::ATTR_PERSISTENT => true ) );
            $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // query the user information
            $sql = "select a.entity_id entity,a.value first,b.value last from customer_entity_varchar a,customer_entity_varchar b where a.entity_id = b.entity_id and a.attribute_id = 5 and b.attribute_id = 7;";
            foreach( $dbh->query( $sql ) as $row ) {
                $this->users[$row['entity']]['entity'] = $row['entity'];
                $this->users[$row['entity']]['first']  = $row['first'];
                $this->users[$row['entity']]['last']   = $row['last'];
            }
            $dbh = null;
            return true;
        } catch (PDOException $e) {
            if ( $this->getConf( 'debugDatabase' ) == 1 ) {
                msg( $e->getMessage(), -1);
            }
        }
        return false;
    }

    /**
     * Load the mail address of the given entity (customer) from Magento
     *
     * @return bool
     */
    protected function _loadMailAddress( $entity ) {
        $this->users[$entity]['mail'] = "default";

        try {
        // get a connection to the database
            $dbh = new PDO( $this->db_dsn, $this->db_user, $this->db_passwd, array( PDO::ATTR_PERSISTENT => true ) );
            $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // query the mail address
            $sql = "select a.entity_id entity,a.email mail from customer_entity a where a.entity_id = {$entity};";
            foreach( $dbh->query( $sql ) as $row ) {
                if ( $entity === $row['entity'] ) {
                    $this->users[$entity]['mail'] = $row['mail'];
                }
            }
            $dbh = null;
            return true;
        } catch (PDOException $e) {
            if ( $this->getConf( 'debugDatabase' ) == 1 ) {
                msg( $e->getMessage(), -1);
            }
        }
        return false;
    }

    /**
     * Load the group of the given entity (customer) from Magento
     *
     * @return bool
     */
    protected function _loadUserGroups( $entity ) {
        $this->users[$entity]['groups'] = array();
        // query only if configured
        if ( $this->getConf( 'includeGroups' ) != 1 ) return true;

        try {
        // get a connection to the database
            $dbh = new PDO( $this->db_dsn, $this->db_user, $this->db_passwd, array( PDO::ATTR_PERSISTENT => true ) );
            $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // query the groups
            $sql = "select a.entity_id entity,b.customer_group_code groups from customer_entity a, customer_group b where a.group_id = b.customer_group_id and a.entity_id = {$entity};";
            foreach( $dbh->query( $sql ) as $row ) {
                if ( $entity === $row['entity'] ) {
                    $name = cleanID( $row['groups'] );
                    $this->users[$entity]['groups'] = array( $name );
                }
            }
            $dbh = null;
            return true;
        } catch (PDOException $e) {
            if ( $this->getConf( 'debugDatabase' ) == 1 ) {
                msg( $e->getMessage(), -1);
            }
        }
        return false;
    }

    /**
     * Load all administrator data from Magento, i.e. just the information require to identify the administrator
     *
     * @return bool
     */
    protected function _loadAdminData() {
        $this->admins = array();
        // query only if configured
        if ( $this->getConf( 'includeAdmins' ) != 1 ) return true;

        try {
        // get a connection to the database
            $dbh = new PDO( $this->db_dsn, $this->db_user, $this->db_passwd, array( PDO::ATTR_PERSISTENT => true ) );
            $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // query the administrator information
            $sql = "select user_id entity,firstname first,lastname last, username user,email mail from admin_user where is_active = 1;";
            foreach( $dbh->query( $sql ) as $row ) {
                $this->admins[$row['entity']]['entity'] = $row['entity'];
                $this->admins[$row['entity']]['user']   = $row['user'];
                $this->admins[$row['entity']]['first']  = $row['first'];
                $this->admins[$row['entity']]['last']   = $row['last'];
                $this->admins[$row['entity']]['mail']   = $row['mail'];
            }
            $dbh = null;
            return true;
        } catch (PDOException $e) {
            if ( $this->getConf( 'debugDatabase' ) == 1 ) {
                msg( $e->getMessage(), -1);
            }
        }
        return false;
    }

    /**
     * Load the roles of the given entity (administrator) from Magento
     *
     * @return bool
     */
    protected function _loadAdminRoles( $entity ) {
        $this->admins[$entity]['roles'] = array();
        // query only if configured
        if ( $this->getConf( 'includeRoles' ) != 1 ) return true;

        if( $this->roles === null ) $this->_loadRoles();

        $stack = array();
        try {
        // get a connection to the database
            $dbh = new PDO( $this->db_dsn, $this->db_user, $this->db_passwd, array( PDO::ATTR_PERSISTENT => true ) );
            $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // find the top level role for the administrator
            $sql = "select role_id id,role_type type,parent_id parent,tree_level level from admin_role where user_id = {$entity} order by tree_level desc,parent_id desc;";
            foreach( $dbh->query( $sql ) as $row ) {
                $xarray = array( $row['id'], $row['type'], $row['parent'], $row['level'] );
                array_push( $stack, $xarray );
            }
        // and search for groups (roles of type G)
            $item = array_shift( $stack );
            while ( $item != null ) {
                if ( $item[1] == "G" ) {
                    $name = $this->roles[$item[0]]['name'];
                    if ( $name != null ) {
                        $name = cleanID( $name );
                        array_push( $this->admins[$entity]['roles'] , $name );
                    }
                }

                if ( $item[1] == "U" ) {
            // query the parent role
                    $sql = "select role_id id,role_type type,parent_id parent,tree_level level from admin_role where role_id = {$item[2]} order by tree_level desc,parent_id desc;";
                    foreach( $dbh->query( $sql ) as $row ) {
                        $xarray = array( $row['id'], $row['type'], $row['parent'], $row['level'] );
                        array_push( $stack, $xarray );
                    }
                }

                $item = array_shift( $stack );
            }
            $dbh = null;
            return true;
        } catch (PDOException $e) {
            if ( $this->getConf( 'debugDatabase' ) == 1 ) {
                msg( $e->getMessage(), -1);
            }
        }
        return false;
    }

    /**
     * Load all administrator roles from Magento
     *
     * @return bool
     */
    protected function _loadRoles() {
        $this->roles = array();

        try {
        // get a connection to the database
            $dbh = new PDO( $this->db_dsn, $this->db_user, $this->db_passwd, array( PDO::ATTR_PERSISTENT => true ) );
            $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // query the administrator roles
            $sql = "select role_id id,role_name name from admin_role where role_type = 'G' order by role_id;";
            foreach( $dbh->query( $sql ) as $row ) {
                $this->roles[$row['id']]['id']   = $row['id'];
                $this->roles[$row['id']]['name'] = $row['name'];
            }
            $dbh = null;
            return true;
        } catch (PDOException $e) {
            if ( $this->getConf( 'debugDatabase' ) == 1 ) {
                msg( $e->getMessage(), -1);
            }
        }
        return false;
    }
}

// vim:ts=4:sw=4:et:
