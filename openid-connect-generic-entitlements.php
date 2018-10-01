<?php
defined( 'ABSPATH' ) or die( 'No script kiddies please!' );
/**
 * @package OpenID_Connect_Generic_Entitlements
 * @version 1.0
 */
/*
Plugin Name: OpenID Connect Generic Entitlements
Description: WordPress plug-in to combine the Open ID Connect Generic Client and Restricted User Access plug-ins with Advantage SSO. 
Author: AdvantageCS
Version: 1.0
Author URI: https://www.advantagecs.com
Text Domain: openid-connect-generic-entitlements
*/

require 'vendor/autoload.php';

class OpenIdConnectEntitlements
{
    public static function getInstance()
    {
        static $instance = false;
        if ( $instance === false ) {
            $instance = new static();
        }
        return $instance;
    }

    protected function __construct() 
    {
        $sso_entitlements_directory = 'acsssodemo.onmicrosoft.com';
        $sso_entitlements_base_url = 'https://sso-test.onadvantagecs.com';
        
        $this->sso_entitlements_client = new GuzzleHttp\Client([
            'base_uri' => $sso_entitlements_base_url . '/api/' . $sso_entitlements_directory . '/',
            'timeout'  => 15.0,
        ]);        

        add_action('wp_login', array( $this, 'map_user_entitlements' ), 10, 2);
    }
    
    private function __clone() {}
    private function __sleep() {}
    private function __wakeup() {}

    public function map_user_entitlements( $user_login, $user ) 
    {
        $access_token = $this->get_user_access_token( $user );
        if (empty( $access_token )) {
            error_log('Unable to query for entitlements without access token.');
            return;
        }
                
        $response = $this->sso_entitlements_client->request('GET', 'me/entitlements', [
            'headers' => [
                'Authorization' => 'Bearer ' . $access_token
            ]
        ]);
        
        if ($response->getStatusCode() == 200) {
            $json = (string)$response->getBody();
            error_log('Received entitlements response for user ' . $user->ID . ': ' . $json);
            $data = json_decode($json);
            $old_levels = rua_get_user_levels($user->ID);
            $user_levels = array();
            
            foreach ($data->scopes as $scope) {
                foreach ($scope->entitlements as $entitlement) {
                    $level = rua_get_level_by_name(strtolower($entitlement->productCode));
                    if ($level) {
                        array_push($user_levels, $level->ID);
                    } else {
                        error_log('No level found for entitlement: '. json_encode($entitlement));
                    }
                }
            }
            
            foreach (array_diff($user_levels, $old_levels) as $level) {
                rua_add_user_level($user->ID, $level);
            }
            foreach (array_diff($old_levels, $user_levels) as $level) {
                rua_remove_user_level($user->ID, $level);
            }
        }
    }
    
    private function get_user_access_token( $user )
    {
    	$token_response = $user->get('openid-connect-generic-last-token-response');
        if (empty($token_response)) {
            error_log('Unable to get entitlements for user ' . $user->ID . ' with no stored token response.');
            return null;
        }
        
        $access_token = $token_response['access_token'];       
        if (empty($access_token)) {
            error_log('Unable to get entitlements for user ' . $user->ID . ' with no access token.');
            error_log('Token response was: '.encode_json($token_response));
            return null;
        }
        
        return $access_token;   
    }
}

$openid_connect_entitlements = OpenIdConnectEntitlements::getInstance();

?>