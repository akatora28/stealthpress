<?php
/**
 * Plugin Name: StealthPress
 * Plugin URI: https://github.com/akatora28/stealthpress
 * Description: Comprehensive protection against PII leakage in WordPress. Blocks user enumeration, hides sensitive data, and enhances privacy across the entire site.
 * Version: 0.1.0
 * Author: Adam Katora
 * Author URI: https://github.com/akatora28
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: stealthpress
 * Domain Path: /languages
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

define('STEALTHPRESS_VERSION', '1.0.0');
define('STEALTHPRESS_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('STEALTHPRESS_PLUGIN_URL', plugin_dir_url(__FILE__));

/**
 * Main plugin class
 */
class StealthPress {

    /**
     * Constructor - add all hooks here
     */
    public function __construct() {
        // Core plugin functionality
        add_action('init', array($this, 'init'));
        
        // Admin-specific hooks
        if (is_admin()) {
            add_action('admin_menu', array($this, 'add_admin_menu'));
            add_action('admin_init', array($this, 'register_settings'));
            add_action('admin_notices', array($this, 'admin_notices'));
        }
        
        // Register activation, deactivation, and uninstall hooks
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }

    /**
     * Initialize the plugin features
     */
    public function init() {
        // Privacy protection features - each can be toggled via admin settings
        $options = get_option('stealthpress_options', array(
            'disable_author_pages' => 'yes',
            'disable_rest_users' => 'yes',
            'disable_user_enumeration' => 'yes',
            'remove_version_info' => 'yes',
            'hide_login_errors' => 'yes',
            'disable_xmlrpc' => 'yes',
            'anonymize_gravatars' => 'yes',
            'hide_comment_author_data' => 'yes',
            'anonymize_rest_responses' => 'yes',
            'protect_media_metadata' => 'yes',
            'disable_rest_api_for_visitors' => 'no',
            'hide_revisions' => 'yes',
        ));
        
        // Disable author pages and archives to prevent user enumeration
        if (isset($options['disable_author_pages']) && $options['disable_author_pages'] === 'yes') {
            add_filter('author_link', array($this, 'disable_author_links'), 10, 3);
            add_action('template_redirect', array($this, 'redirect_author_pages'));
        }
        
        // Disable REST API endpoints that expose user data
        if (isset($options['disable_rest_users']) && $options['disable_rest_users'] === 'yes') {
            add_filter('rest_endpoints', array($this, 'disable_rest_user_endpoints'));
        }
        
        // Optionally completely disable REST API for non-authenticated users
        if (isset($options['disable_rest_api_for_visitors']) && $options['disable_rest_api_for_visitors'] === 'yes') {
            add_filter('rest_authentication_errors', array($this, 'restrict_rest_api_to_logged_in_users'));
        }
        
        // Prevent user enumeration via ?author=X queries
        if (isset($options['disable_user_enumeration']) && $options['disable_user_enumeration'] === 'yes') {
            add_action('template_redirect', array($this, 'prevent_user_enumeration'));
        }
        
        // Remove WordPress version info from headers and scripts
        if (isset($options['remove_version_info']) && $options['remove_version_info'] === 'yes') {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
            add_filter('style_loader_src', array($this, 'remove_version_from_assets'), 10, 2);
            add_filter('script_loader_src', array($this, 'remove_version_from_assets'), 10, 2);
        }
        
        // Hide login errors to prevent username discovery
        if (isset($options['hide_login_errors']) && $options['hide_login_errors'] === 'yes') {
            add_filter('login_errors', array($this, 'custom_login_error_message'));
        }
        
        // Disable XML-RPC functionality to prevent brute force attacks
        if (isset($options['disable_xmlrpc']) && $options['disable_xmlrpc'] === 'yes') {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('wp_headers', array($this, 'remove_x_pingback_header'));
        }
        
        // Anonymize Gravatars to prevent email hashes from being exposed
        if (isset($options['anonymize_gravatars']) && $options['anonymize_gravatars'] === 'yes') {
            add_filter('get_avatar_url', array($this, 'anonymize_gravatar'), 10, 3);
        }
        
        // Hide comment author data
        if (isset($options['hide_comment_author_data']) && $options['hide_comment_author_data'] === 'yes') {
            add_filter('comment_class', array($this, 'remove_comment_author_class'), 10, 5);
            add_filter('get_comment_author_IP', array($this, 'hide_comment_ip'));
            add_filter('get_comment_author_url', array($this, 'hide_comment_author_url'));
            add_filter('get_comment_author_email', array($this, 'hide_comment_author_email'));
            add_filter('comment_author', array($this, 'anonymize_comment_author'), 10, 2);
            add_filter('rest_prepare_comment', array($this, 'filter_comment_rest_response'), 10, 3);
        }
        
        // Anonymize REST API responses
        if (isset($options['anonymize_rest_responses']) && $options['anonymize_rest_responses'] === 'yes') {
            add_filter('rest_prepare_post', array($this, 'filter_post_rest_response'), 10, 3);
            add_filter('rest_prepare_page', array($this, 'filter_post_rest_response'), 10, 3);
            add_filter('rest_prepare_attachment', array($this, 'filter_post_rest_response'), 10, 3);
            add_filter('rest_prepare_revision', array($this, 'filter_post_rest_response'), 10, 3);
        }
        
        // Protect media metadata
        if (isset($options['protect_media_metadata']) && $options['protect_media_metadata'] === 'yes') {
            add_filter('wp_get_attachment_metadata', array($this, 'sanitize_attachment_metadata'), 10, 2);
            add_filter('wp_generate_attachment_metadata', array($this, 'sanitize_attachment_metadata'), 10, 2);
        }
        
        // Hide revisions API
        if (isset($options['hide_revisions']) && $options['hide_revisions'] === 'yes') {
            add_filter('rest_endpoints', array($this, 'disable_rest_revisions_endpoints'));
        }
    }
    
    /**
     * Prevents access to author pages and blocks user enumeration via URL patterns
     * Redirects ALL author page attempts, whether the author exists or not
     */
    public function redirect_author_pages() {
        global $wp_query;
        
        // Catch standard author pages
        if (is_author()) {
            wp_redirect(home_url(), 301);
            exit;
        }
        
        // Catch author URL patterns even before WordPress processes them
        // This ensures we don't leak existence of users via 404 status differences
        $request_uri = $_SERVER['REQUEST_URI'];
        if (preg_match('~^/author/([^/]+)~i', $request_uri) || 
            preg_match('~^/authors/([^/]+)~i', $request_uri)) {
            wp_redirect(home_url(), 301);
            exit;
        }
    }
    
    /**
     * Disables author links
     */
    public function disable_author_links($link, $author_id, $author_nicename) {
        return home_url();
    }
    
    /**
     * Disable REST API endpoints that expose user data
     */
    public function disable_rest_user_endpoints($endpoints) {
        // Remove user endpoints that expose PII
        if (isset($endpoints['/wp/v2/users'])) {
            unset($endpoints['/wp/v2/users']);
        }
        
        if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }
        
        // Also remove the users/me endpoint
        if (isset($endpoints['/wp/v2/users/me'])) {
            unset($endpoints['/wp/v2/users/me']);
        }
        
        return $endpoints;
    }
    
    /**
     * Restrict REST API to logged-in users only
     */
    public function restrict_rest_api_to_logged_in_users($access) {
        if (!is_user_logged_in()) {
            return new WP_Error('rest_api_restricted', __('REST API restricted to authenticated users.', 'stealthpress'), array('status' => 401));
        }
        return $access;
    }
    
    /**
     * Disable REST API revisions endpoints
     */
    public function disable_rest_revisions_endpoints($endpoints) {
        foreach ($endpoints as $route => $endpoint) {
            if (strpos($route, '/revisions') !== false) {
                unset($endpoints[$route]);
            }
        }
        return $endpoints;
    }
    
    /**
     * Prevent user enumeration via various query patterns and URL structures
     */
    public function prevent_user_enumeration() {
        // Common user enumeration methods
        $user_patterns = array(
            // ?author=X
            isset($_GET['author']) && is_numeric($_GET['author']),
            
            // ?author_name=username
            isset($_GET['author_name']),
            
            // ?feed queries on authors
            (isset($_GET['feed']) && (is_author() || (isset($_GET['author']) || isset($_GET['author_name'])))),
            
            // REST API user requests in URL
            (isset($_SERVER['REQUEST_URI']) && stripos($_SERVER['REQUEST_URI'], '/wp-json/wp/v2/users') !== false)
        );
        
        // If any of the patterns match, redirect
        if (in_array(true, $user_patterns, true)) {
            wp_redirect(home_url(), 301);
            exit;
        }
    }
    
    /**
     * Removes version number from asset URLs
     */
    public function remove_version_from_assets($src, $handle) {
        if (strpos($src, 'ver=')) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    }
    
    /**
     * Customize login error message to prevent username discovery
     */
    public function custom_login_error_message($error) {
        return 'Login credentials are incorrect. Please try again.';
    }
    
    /**
     * Remove X-Pingback header to reduce information disclosure
     */
    public function remove_x_pingback_header($headers) {
        if (isset($headers['X-Pingback'])) {
            unset($headers['X-Pingback']);
        }
        return $headers;
    }
    
    /**
     * Anonymize Gravatars to prevent email hash exposure
     */
    public function anonymize_gravatar($url, $id_or_email, $args) {
        // Replace Gravatar URL with a default avatar that doesn't include email hash
        $default_avatar = 'identicon'; // Options: 404, mp, identicon, monsterid, wavatar, retro, robohash, blank
        
        // Generate a random but consistent avatar based on user ID if available
        if (is_numeric($id_or_email)) {
            $seed = $id_or_email;
            $avatar_type = array('identicon', 'monsterid', 'wavatar', 'retro', 'robohash');
            $default_avatar = $avatar_type[$seed % count($avatar_type)];
        } elseif (is_object($id_or_email) && isset($id_or_email->user_id) && $id_or_email->user_id != 0) {
            $seed = $id_or_email->user_id;
            $avatar_type = array('identicon', 'monsterid', 'wavatar', 'retro', 'robohash');
            $default_avatar = $avatar_type[$seed % count($avatar_type)];
        }
        
        $url = remove_query_arg(array('d', 'f', 'r'), $url);
        $url = add_query_arg('d', $default_avatar, $url);
        $url = add_query_arg('f', 'y', $url);
        
        return $url;
    }
    
    /**
     * Remove author-based classes from comments
     */
    public function remove_comment_author_class($classes, $css_class, $comment_id, $comment, $post_id) {
        return array_filter($classes, function($class) {
            return strpos($class, 'comment-author-') !== 0 && 
                   strpos($class, 'byuser') !== 0 && 
                   strpos($class, 'bypostauthor') !== 0;
        });
    }
    
    /**
     * Hide comment IP addresses
     */
    public function hide_comment_ip($ip) {
        return '0.0.0.0';
    }
    
    /**
     * Hide comment author URLs
     */
    public function hide_comment_author_url($url) {
        return '';
    }
    
    /**
     * Hide comment author emails
     */
    public function hide_comment_author_email($email) {
        return '';
    }
    
    /**
     * Anonymize comment author names by using placeholders or pseudonyms
     */
    public function anonymize_comment_author($author, $comment_id) {
        // Get the comment to check if it's by a registered user
        $comment = get_comment($comment_id);
        
        if ($comment && $comment->user_id > 0) {
            // For registered users, provide a consistent pseudonym based on user ID
            $user_id = $comment->user_id;
            $pseudo_names = array('Commenter', 'Reader', 'Visitor', 'Guest', 'Member');
            $name_index = $user_id % count($pseudo_names);
            return $pseudo_names[$name_index] . ' #' . $user_id;
        }
        
        // For anonymous comments
        return 'Anonymous Commenter';
    }
    
    /**
     * Filter comment data in REST API responses
     */
    public function filter_comment_rest_response($response, $comment, $request) {
        if (!is_user_logged_in() || !current_user_can('moderate_comments')) {
            $data = $response->get_data();
            
            // Remove PII
            if (isset($data['author_email'])) {
                unset($data['author_email']);
            }
            if (isset($data['author_ip'])) {
                unset($data['author_ip']);
            }
            if (isset($data['author_url'])) {
                unset($data['author_url']);
            }
            if (isset($data['author_user_agent'])) {
                unset($data['author_user_agent']);
            }
            
            $response->set_data($data);
        }
        
        return $response;
    }
    
    /**
     * Filter post data in REST API responses to remove or anonymize author information
     */
    public function filter_post_rest_response($response, $post, $request) {
        $data = $response->get_data();
        
        // Only hide author info for non-admins
        if (!is_user_logged_in() || !current_user_can('edit_others_posts')) {
            // Remove or anonymize author fields
            if (isset($data['author'])) {
                $data['author'] = 0; // Set to 0 or leave it to not break things
            }
            
            // Remove author links
            if (isset($data['_links']) && isset($data['_links']['author'])) {
                unset($data['_links']['author']);
            }
        }
        
        $response->set_data($data);
        return $response;
    }
    
    /**
     * Sanitize attachment metadata to remove EXIF and other sensitive info
     */
    public function sanitize_attachment_metadata($metadata, $attachment_id) {
        // Don't process if not an image
        if (!is_array($metadata) || !isset($metadata['image_meta'])) {
            return $metadata;
        }

        // Remove potentially sensitive EXIF data
        $sensitive_fields = array(
            'camera', 'created_timestamp', 'aperture', 'focal_length', 'iso',
            'shutter_speed', 'title', 'caption', 'credit', 'copyright',
            'focal_length_35mm', 'keywords', 'latitude', 'longitude', 'gps'
        );
        
        foreach ($sensitive_fields as $field) {
            if (isset($metadata['image_meta'][$field])) {
                $metadata['image_meta'][$field] = '';
            }
        }
        
        return $metadata;
    }
    
    /**
     * Add plugin settings page to the admin menu
     */
    public function add_admin_menu() {
        add_options_page(
            'StealthPress Settings',
            'StealthPress',
            'manage_options',
            'stealthpress',
            array($this, 'display_settings_page')
        );
    }
    
    /**
     * Register plugin settings
     */
    public function register_settings() {
        register_setting('stealthpress_options_group', 'stealthpress_options');
        
        add_settings_section(
            'stealthpress_settings_section',
            'Privacy Protection Settings',
            array($this, 'settings_section_callback'),
            'stealthpress'
        );
        
        $this->add_settings_fields();
    }
    
    /**
     * Add settings fields
     */
    public function add_settings_fields() {
        $fields = array(
            'disable_author_pages' => 'Disable Author Pages',
            'disable_rest_users' => 'Disable REST API User Endpoints',
            'disable_user_enumeration' => 'Prevent User Enumeration',
            'remove_version_info' => 'Remove WordPress Version Info',
            'hide_login_errors' => 'Hide Specific Login Errors',
            'disable_xmlrpc' => 'Disable XML-RPC Functionality',
            'anonymize_gravatars' => 'Anonymize Gravatars',
            'hide_comment_author_data' => 'Hide Comment Author Data',
            'anonymize_rest_responses' => 'Anonymize REST API Responses',
            'protect_media_metadata' => 'Protect Media File Metadata',
            'disable_rest_api_for_visitors' => 'Disable REST API for Non-Logged-In Users',
            'hide_revisions' => 'Hide Revisions in REST API',
        );
        
        foreach ($fields as $id => $title) {
            add_settings_field(
                'stealthpress_' . $id,
                $title,
                array($this, 'render_settings_field'),
                'stealthpress',
                'stealthpress_settings_section',
                array(
                    'id' => $id,
                    'label_for' => 'stealthpress_' . $id,
                )
            );
        }
    }
    
    /**
     * Settings section callback
     */
    public function settings_section_callback() {
        echo '<p>Configure which privacy protection features you want to enable. All options are recommended for maximum privacy.</p>';
        echo '<p><strong>Note:</strong> The option to disable REST API for non-logged-in users is off by default as it may break frontend functionality on some sites.</p>';
    }
    
    /**
     * Render settings field
     */
    public function render_settings_field($args) {
        $options = get_option('stealthpress_options', array(
            'disable_author_pages' => 'yes',
            'disable_rest_users' => 'yes',
            'disable_user_enumeration' => 'yes',
            'remove_version_info' => 'yes',
            'hide_login_errors' => 'yes',
            'disable_xmlrpc' => 'yes',
            'anonymize_gravatars' => 'yes',
        ));
        
        $id = $args['id'];
        $checked = isset($options[$id]) && $options[$id] === 'yes' ? 'checked' : '';
        
        echo '<input type="checkbox" id="stealthpress_' . esc_attr($id) . '" name="stealthpress_options[' . esc_attr($id) . ']" value="yes" ' . $checked . '>';
    }
    
    /**
     * Display settings page
     */
    public function display_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <div class="card" style="max-width: 100%; margin-bottom: 20px; padding: 20px; background-color: #fff; border: 1px solid #c3c4c7; border-left: 4px solid #2271b1; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
                <h2>About StealthPress</h2>
                <p>StealthPress helps protect your WordPress site against PII (Personally Identifiable Information) leakage by blocking common information disclosure vectors.</p>
                <p>By disabling various WordPress features that expose user information, you can enhance privacy and security for your site and its users.</p>
            </div>
            
            <form action="options.php" method="post">
                <?php
                settings_fields('stealthpress_options_group');
                do_settings_sections('stealthpress');
                submit_button('Save Settings');
                ?>
            </form>
            
            <div class="card" style="max-width: 100%; margin-top: 20px; padding: 10px 20px; background-color: #fff; border: 1px solid #c3c4c7; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
                <h3>Privacy Test Tools</h3>
                <p>Test your site for user enumeration vulnerabilities:</p>
                <ul style="list-style-type: disc; padding-left: 20px;">
                    <li>Try accessing <code><?php echo esc_html(home_url('/?author=1')); ?></code> - Should redirect to homepage</li>
                    <li>Try accessing <code><?php echo esc_html(home_url('/wp-json/wp/v2/users')); ?></code> - Should return "Sorry, you are not allowed to list users."</li>
                    <li>Try accessing <code><?php echo esc_html(home_url('/author/admin/')); ?></code> - Should redirect to homepage</li>
                </ul>
            </div>
        </div>
        <?php
    }
    
    /**
     * Plugin activation
     */
    public function activate() {
        // Add default options if not already set
        if (!get_option('stealthpress_options')) {
            update_option('stealthpress_options', array(
                'disable_author_pages' => 'yes',
                'disable_rest_users' => 'yes',
                'disable_user_enumeration' => 'yes',
                'remove_version_info' => 'yes',
                'hide_login_errors' => 'yes',
                'disable_xmlrpc' => 'yes',
                'anonymize_gravatars' => 'yes',
                'hide_comment_author_data' => 'yes',
                'anonymize_rest_responses' => 'yes',
                'protect_media_metadata' => 'yes',
                'disable_rest_api_for_visitors' => 'no', // Default to no to avoid breaking legitimate usage
                'hide_revisions' => 'yes',
            ));
        }
    }
    
    /**
     * Add admin notice with privacy scan results
     */
    public function admin_notices() {
        // Only show to admins
        if (!current_user_can('manage_options')) {
            return;
        }
        
        // Display privacy issues found
        $issues = $this->check_privacy_issues();
        
        if (!empty($issues)) {
            echo '<div class="notice notice-warning is-dismissible">';
            echo '<h3>StealthPress Privacy Scan</h3>';
            echo '<p>The following potential privacy issues were detected:</p>';
            echo '<ul style="list-style-type: disc; padding-left: 20px;">';
            
            foreach ($issues as $issue) {
                echo '<li>' . esc_html($issue) . '</li>';
            }
            
            echo '</ul>';
            echo '<p>Configure <a href="' . admin_url('options-general.php?page=stealthpress') . '">StealthPress settings</a> to resolve these issues.</p>';
            echo '</div>';
        }
    }
    
    /**
     * Scan for common privacy issues
     */
    private function check_privacy_issues() {
        $issues = array();
        $options = get_option('stealthpress_options', array());
        
        // Check for enabled author pages
        if (empty($options['disable_author_pages']) || $options['disable_author_pages'] !== 'yes') {
            $issues[] = 'Author pages are enabled, which can expose usernames and post history.';
        }
        
        // Check for REST API user endpoints
        if (empty($options['disable_rest_users']) || $options['disable_rest_users'] !== 'yes') {
            $issues[] = 'REST API user endpoints are enabled, which expose user information via /wp-json/wp/v2/users.';
        }
        
        // Check if comments are enabled
        if (get_option('default_comment_status') === 'open') {
            if (empty($options['hide_comment_author_data']) || $options['hide_comment_author_data'] !== 'yes') {
                $issues[] = 'Comments are enabled and comment author data is not being protected.';
            }
        }
        
        // Check for exposed Gravatars
        if (empty($options['anonymize_gravatars']) || $options['anonymize_gravatars'] !== 'yes') {
            $issues[] = 'Gravatar images may expose email hashes of your users.';
        }
        
        // Check for XML-RPC
        if (empty($options['disable_xmlrpc']) || $options['disable_xmlrpc'] !== 'yes') {
            $issues[] = 'XML-RPC is enabled, which can be used for user enumeration and brute force attacks.';
        }
        
        return $issues;
    }
    
    /**
     * Plugin deactivation
     */
    public function deactivate() {
        // Cleanup if needed
    }
}

// Initialize the plugin
$stealthpress = new StealthPress();