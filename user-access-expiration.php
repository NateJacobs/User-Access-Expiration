<?php

/**
 *	Plugin Name: User Access Expiration
 *	Plugin URI: https://github.com/NateJacobs/User-Access-Expiration
 *	Description: Expires a user's access to a site after a specified number of days based upon the registration date. The administrator can restore a user's access from the user's profile page.
 *	Version: 1.0
 *	License: GPL V2
 *	Author: Nate Jacobs <nate@natejacobs.org>
 *	Author URI: http://natejacobs.org
 */
 
class UserAccessExpiration
{	
	// the plugin options meta key	
	CONST option_name = "user_access_expire_options";
	// the custom user meta key
	CONST user_meta = 'uae_user_access_expired';
	
	// hook into user registration and authentication
	public function __construct()
	{
		// since 0.1
		add_action( 'user_register', array( $this, 'set_expiration_timer' ) );
		add_filter( 'authenticate', array( $this, 'check_user_access_status' ), 10, 3 );
		add_action( 'admin_menu', array( $this, 'add_user_expire_submenu' ) );
		add_action('admin_init', array( $this, 'options_init' ));
		register_activation_hook( __FILE__, array( $this, 'activation' ) );
		// since 0.2
		add_action( 'show_user_profile', array( $this, 'add_user_profile_fields' ) );
		add_action( 'edit_user_profile', array( $this, 'add_user_profile_fields' ) );
		add_action( 'personal_options_update', array( $this, 'save_user_profile_fields' ) );
		add_action( 'edit_user_profile_update', array( $this, 'save_user_profile_fields' ) );
	}
	
	/** 
	 *	Activation
	 *
	 *	Upon plugin activation create a custom user meta key of user_access_expired
	 *	for all users and set the value to false (access is allowed). Also adds
	 *	default settings for the log in error message and number of days of access.
	 *
	 *	@author		Nate Jacobs
	 *	@since		0.1
	 *	@update		0.2 (add_option)
	 */
	public function activation()
	{
		// limit user data returned to just the id
		$args = array( 'fields' => 'ID' );
		$users = get_users( $args );
		// loop through each user
		foreach ( $users as $user )
		{
			// add the custom user meta to the wp_usermeta table
			add_user_meta( $user, self::user_meta, 'false' );
		}
		
		// add option with base information
		add_option( 
			self::option_name, 
			array( 
				'error_message' => 'To gain access please contact us.',
				'number_days' => '30'
			),
			'',
			'yes'
		);
	}
	
	/** 
	 *	Set Expiration Timer
	 *
	 *	Adds a custom user meta key of user_access_expired when a new user is registered.
	 *	It sets the initial value to false. This indicates the user still has access.
	 *
	 *	@author		Nate Jacobs
	 *	@since		0.1
	 *
	 *	@param	int	$user_id
	 */
	public function set_expiration_timer( $user_id )
	{
		add_user_meta( $user_id, self::user_meta, 'false' );
	}
	
	/** 
	 *	Check User Access Status
	 *
	 *	Takes the credentials entered by the user on the login form and grabs the user_id
	 *	from the login name. Gets the value of the user meta field set up by the 
	 *	set_expiration_timer method. Also gets the user registered date/time. If the specified 
	 *	time frame has elapsed then the user is denied access.
	 *
	 *	@author		Nate Jacobs
	 *	@since		0.1
	 *	@updated	0.4
	 *
	 *	@param	string	$user
	 *	@param	string	$user_login
	 *	@param	string	$password
	 *	@return	mixed	$user ( either an error or valid user )	
	 */
	public function check_user_access_status( $user, $user_login, $password )
	{
		// get user data by login
		$user_info = get_user_by( 'login', $user_login );
		$access_expiration = '';
		$expire_time = '';
		$new_time = '';
		$expired = '';
		
		// if the user has entered something in the user name box
		if ( $user_info )
		{
			// get the plugin options
			$options = get_option( self::option_name );
			// get the custom user meta defined earlier
			$access_expiration = get_user_meta( $user_info->ID, self::user_meta, true );
			// get the user registered time
			$register_time = strtotime( $user_info->user_registered );
			// get the date in unix time that is the specified number of elapsed days from the registered date
			$expire_time = strtotime( '+'.$options['number_days'].'days', $register_time );
			
			if( $expire_time < date( 'U' ) )
			{
				if( user_can($user_info->ID, 'manage_options') )
				{
					$expired = false;
				}
				else
				{
					$expired = true;
				}
			}
		}
		
		if ( empty( $user_login ) || empty( $password ) )
		{
			if ( empty( $username ) )
				$user = new WP_Error('empty_username', __('<strong>ERROR</strong>: The username field is empty.'));
	
			if ( empty( $password ) )
				$user = new WP_Error('empty_password', __('<strong>ERROR</strong>: The password field is empty.'));
		}
		else
		{
			// if the custom user meta field is true ( access is expired ) or the current date is more than
			// the specified number of days past the registered date, deny access
			if ( $access_expiration == 'true' || $expired )
			{
				// change the custom user meta to show access is now denied
				update_user_meta( $user_info->ID, self::user_meta, 'true' );
				// register a new error with the error message set above
				$user = new WP_Error( 'access_denied', __( '<strong>Your access to the site has expired.</strong><br>'.$options['error_message'] ) );
				// deny access to login and send back to login page
				remove_action( 'authenticate', 'wp_authenticate_username_password', 20 );
			}
		}	
		return $user;
	}
	
	/** 
	 *	Add Submenu Page
	 *
	 *	Adds a submenu page to settings page for the user entered settings.
	 *
	 *	@author		Nate Jacobs
	 *	@since		0.2
	 */
	public function add_user_expire_submenu()
	{
		add_submenu_page(
			'options-general.php',
			__( 'User Access Expiration' ),
			__( 'User Expiration' ),
			'manage_options',
			'user-access-expiration',
			array( $this, 'user_access_expire_settings' )
		);
	}
	
	/** 
	 *	Initiate Options
	 *
	 *	Create the options needed for the settings API.
	 *
	 *	@author		Nate Jacobs
	 *	@since		0.2
	 */
	public function options_init()
	{
		register_setting( 
			'user_access_expire_options',
			'user_access_expire_options',
			array( $this, 'user_access_expire_options_validate' )
		);
		add_settings_section(
			'primary_section',
			'', //section title
			array( $this, 'primary_section_text' ),
			__FILE__
		);
		
		$settings_fields = array(
			array(
				'id' => 'number_of_days',
				'title' => 'Number of Days',
				'function' => 'setting_number_days',
				'section' => 'primary_section'
			),
			array(
				'id' => 'error_message',
				'title' => 'Error Message',
				'function' => 'setting_error_message',
				'section' => 'primary_section'
			),
		);
		
		foreach( $settings_fields as $settings )
		{
			add_settings_field(
				$settings['id'],
				$settings['title'],
				array( $this, $settings['function'] ),
				__FILE__,
				$settings['section']
			);
		}
	}
	
	/** 
	 *	Primary Section Text
	 *
	 *	Not used at this point, but method provided for potential future use.
	 *
	 *	@author		Nate Jacobs
	 *	@since		0.2
	 */
	public function primary_section_text()
	{
		
	}
	
	/** 
	 *	Number of Days to Expire
	 *
	 *	Provides field to allow administrators to set how many days a user's access
	 *	should be expired after.
	 *
	 *	@author		Nate Jacobs
	 *	@since		0.2
	 */
	public function setting_number_days()
	{
		$options = get_option( self::option_name );
		//{$this->get_settings( 'user-access-expiration' )}
		echo "<input id='number_of_days' name='user_access_expire_options[number_days]' size='10' type='text' value='{$options['number_days']}' />";
		echo "<br>How many days after registration should a user have access for?";
	}
	
	/** 
	 *	Error Message 
	 *
	 *	Provides field to allow administrators to set the error message a user sees
	 *	once their access has expired.
	 *
	 *	@author		Nate Jacobs
	 *	@since		0.2
	 */
	public function setting_error_message()
	{
		$options = get_option( self::option_name );
		echo "<input id='error_message' name='user_access_expire_options[error_message]' size='75' type='text' value='{$options['error_message']}' />";
		echo "<br>This message is displayed to a user once their access is denied.";
		echo "<br><b>Example:</b> To gain access please contact us at myemail@myexample.com.";	
	}
	
	/** 
	 *	Validate and Clean Options
	 *
	 *	Takes the values entered by the user and validates and cleans the input
	 *	to prevent xss or other mean things.
	 *	Checks the number of days entered value to make sure it is a number.
	 *
	 *	@author		Nate Jacobs
	 *	@since		0.2
	 */
	public function user_access_expire_options_validate( $input )
	{
		$valid_input['error_message'] =  wp_filter_nohtml_kses( $input['error_message'] );
		$input['number_days'] =  trim( $input['number_days'] );
		$valid_input['number_days'] = ( is_numeric( $input['number_days'] ) ) ? $input['number_days'] : '';
		
		if ( is_numeric( $input['number_days'] ) == FALSE )
		{
			add_settings_error(
				$input['number_days'],
				'_txt_numeric_error',
				__( 'Sorry that is not a number. Please enter a number.	' ),
				'error'
			);
		}
		return $valid_input;
	}
	
	/** 
	 *	Add Content for Settings Page
	 *
	 *	Create the settings page for the plugin.
	 *
	 *	@author		Nate Jacobs
	 *	@since		0.2
	 */
	public function user_access_expire_settings()
	{
		?>
		<div class="wrap">
			<?php settings_errors(); ?>
			<div class="icon32" id="icon-options-general"><br></div>
			<h2><?php _e( 'User Access Expiration Settings' ); ?></h2>
			<form method="post" action="options.php">
				<?php settings_fields( 'user_access_expire_options' ); ?>
				<?php do_settings_sections( __FILE__ ); ?>
				<p class="submit">
				<input type="submit" class="button-primary" value="<?php _e( 'Save Changes' ) ?>" />
				</p>
			</form>
		</div>
		<?php
	}
	
	/** 
	 *	Add User Profile Field
	 *
	 *	Adds an extra field to the user profile page. Allows an administrator
	 *	to change a specific user's access. 
	 *
	 *	@author		Nate Jacobs
	 *	@since		0.2
	 *
	 *	@param	object	$user
	 */
	 public function add_user_profile_fields( $user )
	 {
	 	if ( current_user_can( 'manage_options', $user->ID ) )
		{
		?>
		<h3>User Access Expiration</h3>
		<table class="form-table">
		<tr>
			<th>Registered date: </th>
			<td><?php echo date_i18n(get_option('date_format').' '.get_option('time_format') ,strtotime(get_the_author_meta( 'user_registered', $user->ID ))); ?></td>
		</tr>
		<tr>
			<th><label for="user-access">Does this person have access to the site?</label></th>
			<td>
				<?php $access = get_the_author_meta( self::user_meta, $user->ID ); ?>
				<select id="user-access" name="user-access" class="regular-text">
					<option value="false" <?php if ( $access == 'false' ) echo "selected"; ?>>Yes</option>
					<option value="true" <?php if ( $access == 'true' ) echo "selected"; ?>>No</option>
				</select>
			</td>
		</tr>
		</table>
		<?php
		}
	 }
	
	/** 
	  *	Save User Profile Fields
	  *
	  *	Saves the access value for the user.
	  *
	  *	@author		Nate Jacobs
	  *	@since		0.2
	  *
	  *	@param	int	$user_id
	  */ 
	public function save_user_profile_fields( $user_id )
	{
		if( !current_user_can( 'manage_options', $user_id ) )
			return false;
		update_user_meta( $user_id, self::user_meta, $_POST['user-access'] );
	}
}
new UserAccessExpiration();