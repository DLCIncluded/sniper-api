<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: *');
date_default_timezone_set('America/Detroit');

require("./config.php");

//Include JWT for PHP
require_once 'jwt/src/BeforeValidException.php';
require_once 'jwt/src/ExpiredException.php';
require_once 'jwt/src/SignatureInvalidException.php';
require_once 'jwt/src/JWT.php';
use \Firebase\JWT\JWT;

//set our base response with an 'error' of false
$result = array('error'=>false);

//get action from the URL
if(isset($_GET['action'])){
	$action = $_GET['action'];
}else {
	return;
}

//user controls
if($action === "login") {
	if(!isset($_POST['username'])){
		// http_response_code(401);
		//no username given 
		$result['error'] = true;
		$result['message'] = "Missing Username.";
		echo json_encode($result); 
        return;
	}else{
		$username = $_POST['username'];
	}
	if(!isset($_POST['password'])){
		//no username given 
		$result['error'] = true;
		$result['message'] = "Missing Password.";
		echo json_encode($result); 
        return;
	}else{
		$password = $_POST['password'];
	}

	if(!preg_match("/^(?=[a-zA-Z0-9._]{4,25}$)(?!.*[_.]{2})[^_.].*[^_.]$/", $username)){
        //if there is a non-approved character 
        $result['error']=true;
        $result['message'] = "Invalid username";
		// Password requirements
		// Only contains alphanumeric characters, underscore and dot.
		// Underscore and dot can't be at the end or start of a username (e.g _username / username_ / .username / username.).
		// Underscore and dot can't be next to each other (e.g user_.name).
		// Underscore or dot can't be used multiple times in a row (e.g user__name / user..name).
		// Number of characters must be between 4 to 25.
        echo json_encode($result); // have to print here as we are quitting the rest of the file with return
        return;
    }
	
	$sql = $conn->query("SELECT * FROM users WHERE username='$username'");
    if($sql->num_rows == 1){
		$row = $sql->fetch_assoc();
		//create easy to use vars for following user checks
		$id = $row['id'];
		$username = $row['username'];
		$email = $row['email'];
		$passwordhash = $row['password'];
		$admin = $row['admin'];

		//verify password provided matches the db hash
		$pwmatch = password_verify($password, $passwordhash);
		if(!$pwmatch){
			//if our passwords do not match db, error out and let them know. 
			$result['error'] = true;
			$result['message'] = "Incorrect Password.";
			echo json_encode($result); 
			return;
		}
		// at this point we are good to create the token, and send the info back to the user
		$IAT = time(); //get current time for issued at
		$NBF = 1357000000; //9 years ago - this is "Not BeFore", not sure if its required... guess could make it so you have to wait to login.. but idk why
		$EXP = $IAT + $JWT_EXPIRES_IN; // add the expires in amount from config in seconds
		$token = array(
			"iss" => $JWT_ISS,
			"aud" => $JWT_AUD,
			"iat" => $IAT,
			"nbf" => $NBF,
			"exp" => $EXP,
			"data" => array(
				"id" => $id,
				"username" => $username
			)
		);
		
		$jwt = JWT::encode($token, $JWT_KEY);
		
		$result['message'] = "successfully logged in";
		$result['token'] = $jwt;

		$result['id'] = $id;
		$result['username'] = $username;
		$result['email'] = $email;
		$result['isadmin'] = $admin;
	}else{
        //no user found
		$result['error'] = true;
		$result['message'] = "NO USER FOUND.";
		echo json_encode($result); 
        return;
    }
}

if($action === "register") {
	if(!isset($_POST['username'])){
		//no username given 
		$result['error'] = true;
		$result['message'] = "Missing Username.";
		echo json_encode($result); 
        return;
	}else{
		$username = $_POST['username'];
	}
	if(!isset($_POST['password'])){
		//no password given 
		$result['error'] = true;
		$result['message'] = "Missing Password.";
		echo json_encode($result); 
        return;
	}else{
		$password = $_POST['password'];
	}
	if(!isset($_POST['email'])){
		//no username given 
		$result['error'] = true;
		$result['message'] = "Missing email.";
		echo json_encode($result); 
		return;
	}else{
		$email = $_POST['email'];
	}

	if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
        //if email is invalid

        $result['error']=true;
        $result['message'] = "Invalid Email.";
        echo json_encode($result);
        return;   
    }

	if(!preg_match("/^(?=[a-zA-Z0-9._]{4,25}$)(?!.*[_.]{2})[^_.].*[^_.]$/", $username)){
        //if there is a non-approved character 
        $result['error']=true;
        $result['message'] = "Invalid username";
		// Password requirements
		// Only contains alphanumeric characters, underscore and dot.
		// Underscore and dot can't be at the end or start of a username (e.g _username / username_ / .username / username.).
		// Underscore and dot can't be next to each other (e.g user_.name).
		// Underscore or dot can't be used multiple times in a row (e.g user__name / user..name).
		// Number of characters must be between 4 to 25.
        echo json_encode($result); // have to print here as we are quitting the rest of the file with return
        return;
    }

	if(!password_strength_check($password)){
		$result['error']=true;
        $result['message'] = "Password does not meet requirements.";
        echo json_encode($result);
        return; 
	}

	//check if username taken
    $sql = $conn->query("SELECT * FROM users WHERE username='$username'");
    if($sql->num_rows >= 1){
        //if we have a user, error out
        $result['error']=true;
        $result['message'] = "The username $username is already in use.";
        echo json_encode($result); // have to print here as we are quitting the rest of the file with return
        return;
    }

    //check if email taken
    $sql = $conn->query("SELECT * FROM users WHERE email='$email'");
    if($sql->num_rows >= 1){
        //if we have a user, error out
        $result['error']=true;
        $result['message'] = "The email $email is already in use.";
        echo json_encode($result); // have to print here as we are quitting the rest of the file with return
        return;
    }

	$password = password_hash($password, PASSWORD_BCRYPT); //create password hash

    //at this point user is valid to input into db
    
    $sql = $conn->query("INSERT INTO users (username,email,password,admin) 
        VALUES 
        ('$username','$email','$password',false);
    ");

	if($sql){
		$result['message'] = "Account Successfully Registered.";
	}
	else {
		$result['error'] = true;
		$result['message'] = "There was an error saving to the DB";
	}

}

if($action === "newlink"){



	if(!isset($_POST['user_id'])){
		//no user id given 
		$result['error'] = true;
		$result['message'] = "Missing id.";
		echo json_encode($result); 
        return;
	}else{
		$userid = $_POST['user_id'];
	}
	

	if(!isset($_POST['token'])){
		//no token given 
		$result['error'] = true;
		$result['message'] = "Missing token.";
		echo json_encode($result); 
        return;
	}else{
		$token = $_POST['token'];
	}
	
	if(!validate_token($token)){
		//if token invalid for whatever reason, stop now
		$result['error'] = true;
		$result['message'] = "Token Invalid.";
		echo json_encode($result); 
        return;
	}else{
		$user = extract_user_token($token);
		// $id = $user['data']->id;
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
		$result['error'] = true;
		$result['message'] = "User not match. $userid";
		echo json_encode($result); 
        return;
	}

	$sql = $conn->query("SELECT * FROM users WHERE id=$userid");

	if($sql->num_rows != 1){
		//we cannot find a user with that id
		$result['error'] = true;
		$result['message'] = "Invalid User id provided.";
		echo json_encode($result); 
        return;
	}

	$row = $sql->fetch_assoc();
	$admin = $row['admin'];
	if($admin==false){
		//user is not set as admin
		$result['error'] = true;
		$result['message'] = "Unauthorized.";
		echo json_encode($result); 
        return;
	}

	// now that we know the user exists lets start verify that the user sent all the required data

	if(!isset($_POST['link_name'])){
		//no list_name given 
		$result['error'] = true;
		$result['message'] = "Missing Link Name.";
		echo json_encode($result); 
        return;
	}else{
		$link_name = $_POST['link_name'];
	}

	if(!isset($_POST['link_url'])){
		//no list_url given 
		$result['error'] = true;
		$result['message'] = "Missing Link url.";
		echo json_encode($result); 
        return;
	}else{
		$link_url = $_POST['link_url'];
	}

	if(!isset($_POST['link_description'])){
		$link_description = ''; 
	}else{
		$link_description = $_POST['link_description'];
	}

	if(!isset($_POST['link_icon'])){
		$link_icon = ''; 
	}else{
		$link_icon = $_POST['link_icon'];
	}
	if(!isset($_POST['link_color'])){
		$link_color = ''; 
	}else{
		$link_color = $_POST['link_color'];
	}
	if(!isset($_POST['link_border_color'])){
		$link_border_color = ''; 
	}else{
		$link_border_color = $_POST['link_border_color'];
	}


	//at this point we have what we need, lets create the link and give the user access to it

	$sql = $conn->query("INSERT INTO links (link_name,link_desc,link_url,link_icon,link_color,link_border_color) 
        VALUES 
        ('$link_name', '$link_description', '$link_url', '$link_icon', '$link_color', '$link_border_color');
    ");

	if(!$sql){
		$result['error'] = true;
		$result['message'] = "There was an error saving the link";
		echo json_encode($result); 
        return;
	}

	// at this point link should be created
	$result['message'] = "Successfully created link: $link_name";

}

if($action === "updatelink"){
	if(!isset($_POST['user_id'])){
		//no user id given 
		$result['error'] = true;
		$result['message'] = "Missing id.";
		echo json_encode($result); 
        return;
	}else{
		$userid = $_POST['user_id'];
	}
	

	if(!isset($_POST['token'])){
		//no token given 
		$result['error'] = true;
		$result['message'] = "Missing token.";
		echo json_encode($result); 
        return;
	}else{
		$token = $_POST['token'];
	}

	if(!validate_token($token)){
		//if token invalid for whatever reason, stop now
		$result['error'] = true;
		$result['message'] = "Token Invalid.";
		echo json_encode($result); 
        return;
	}else{
		$user = extract_user_token($token);
		// $id = $user['data']->id;
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
		$result['error'] = true;
		$result['message'] = "Token Invalid.";
		echo json_encode($result); 
        return;
	}

	$sql = $conn->query("SELECT * FROM users WHERE id=$userid");

	if($sql->num_rows != 1){
		//we cannot find a user with that id
		$result['error'] = true;
		$result['message'] = "Invalid User id provided.";
		echo json_encode($result); 
        return;
	}

	$row = $sql->fetch_assoc();
	$admin = $row['admin'];
	if($admin==false){
		//user is not set as admin
		$result['error'] = true;
		$result['message'] = "Unauthorized.";
		echo json_encode($result); 
        return;
	}

	// now that we know the user exists lets start verify that the user sent all the required data

	if(!isset($_POST['link_name'])){
		//no list_name given 
		$result['error'] = true;
		$result['message'] = "Missing Link Name.";
		echo json_encode($result); 
        return;
	}else{
		$link_name = $_POST['link_name'];
	}

	if(!isset($_POST['link_id'])){
		//no list_id given 
		$result['error'] = true;
		$result['message'] = "Missing Link id.";
		echo json_encode($result); 
        return;
	}else{
		$link_id = $_POST['link_id'];
	}

	if(!isset($_POST['link_url'])){
		//no list_url given 
		$result['error'] = true;
		$result['message'] = "Missing Link url.";
		echo json_encode($result); 
        return;
	}else{
		$link_url = $_POST['link_url'];
	}

	if(!isset($_POST['link_description'])){
		$link_description = ''; 
	}else{
		$link_description = $_POST['link_description'];
	}

	if(!isset($_POST['link_icon'])){
		$link_icon = ''; 
	}else{
		$link_icon = $_POST['link_icon'];
	}
	if(!isset($_POST['link_color'])){
		$link_color = ''; 
	}else{
		$link_color = $_POST['link_color'];
	}
	if(!isset($_POST['link_border_color'])){
		$link_border_color = ''; 
	}else{
		$link_border_color = $_POST['link_border_color'];
	}


	//at this point we have what we need, lets create the link and give the user access to it

	// $sql = $conn->query("INSERT INTO links (link_name,link_desc,link_url,link_icon,link_color,link_border_color) 
    //     VALUES 
    //     ('$link_name', '$link_description', '$link_url', '$link_icon', '$link_color', '$link_border_color');
    // ");
	$sql = $conn->query("UPDATE links SET
		link_name='$link_name', 
		link_desc='$link_description', 
		link_url='$link_url', 
		link_icon='$link_icon', 
		link_color='$link_color', 
		link_border_color='$link_border_color' 
		WHERE id='$link_id'
    ");

	if(!$sql){
		$result['error'] = true;
		$result['message'] = "There was an error saving the link";
		echo json_encode($result); 
        return;
	}

	// at this point link should be created
	$result['message'] = "Successfully updated link: $link_name";

}

if($action === "getlinks"){

	$sql = $conn->query("SELECT * FROM links");
	$links = array();
	while($row = $sql->fetch_assoc()){
		$link_id = $row['id'];
		$link_name = $row['link_name'];
		$link_description = $row['link_desc'];
		$link_url = $row['link_url'];
		$link_icon = $row['link_icon'];
		$link_color = $row['link_color'];
		$link_border_color = $row['link_border_color'];

		$link = array(
			'link_id' => $link_id,
			'link_name' => $link_name,
			'link_description' => $link_description,
			'link_url' => $link_url,
			'link_icon' => $link_icon,
			'link_color' => $link_color,
			'link_border_color' => $link_border_color,
		);
		array_push($links,$link);
	}
	$result['message'] = "Successfully pulled links.";
	$result['links'] = $links;

}

if($action === "deletelink"){
	if(!isset($_POST['user_id'])){
		//no user id given 
		$result['error'] = true;
		$result['message'] = "Missing id.";
		echo json_encode($result); 
        return;
	}else{
		$userid = $_POST['user_id'];
	}

	if(!isset($_POST['link_id'])){
		//no link id given 
		$result['error'] = true;
		$result['message'] = "Missing id.";
		echo json_encode($result); 
        return;
	}else{
		$link_id = $_POST['link_id'];
	}
	

	if(!isset($_POST['token'])){
		//no token given 
		$result['error'] = true;
		$result['message'] = "Missing token.";
		echo json_encode($result); 
        return;
	}else{
		$token = $_POST['token'];
	}

	if(!validate_token($token)){
		//if token invalid for whatever reason, stop now
		$result['error'] = true;
		$result['message'] = "Token Invalid.";
		echo json_encode($result); 
        return;
	}else{
		$user = extract_user_token($token);
		// $id = $user['data']->id;
	}

	if($user['data']->id !== $userid){
		//if the user sends a token that does not belong to the current logged in user
		$result['error'] = true;
		$result['message'] = "Token Invalid.";
		echo json_encode($result); 
        return;
	}

	$sql = $conn->query("SELECT * FROM users WHERE id=$userid");

	if($sql->num_rows != 1){
		//we cannot find a user with that id
		$result['error'] = true;
		$result['message'] = "Invalid User id provided.";
		echo json_encode($result); 
        return;
	}

	$row = $sql->fetch_assoc();
	$admin = $row['admin'];
	if($admin==false){
		//user is not set as admin
		$result['error'] = true;
		$result['message'] = "Unauthorized.";
		echo json_encode($result); 
        return;
	}

	//at this point we have what we need, lets create the link and give the user access to it

	$sql = $conn->query("DELETE FROM links WHERE id='$link_id'");

	if(!$sql){
		$result['error'] = true;
		$result['message'] = "There was an error deleting the link";
		echo json_encode($result); 
        return;
	}

	// at this point link should be created
	$result['message'] = "Successfully deleted link";

}


function validate_token($token){
	global $JWT_KEY;
	try {
		$decoded = JWT::decode($token, $JWT_KEY, array('HS256'));
		return true;
	} catch(\Firebase\JWT\ExpiredException $e) {
        return false;
	}
}

function extract_user_token($token){
	global $JWT_KEY;
	try {
		$decoded = JWT::decode($token, $JWT_KEY, array('HS256'));
		return (array) $decoded;
	} catch(Exception $e) {
        return false;
	}
}

function password_strength_check($password, $min_len = 8, $max_len = 255, $req_digit = 1, $req_lower = 1, $req_upper = 1, $req_symbol = 1) {
    // Build regex string depending on requirements for the password
    $regex = '/^';
    if ($req_digit == 1) { $regex .= '(?=.*\d)'; }              // Match at least 1 digit
    if ($req_lower == 1) { $regex .= '(?=.*[a-z])'; }           // Match at least 1 lowercase letter
    if ($req_upper == 1) { $regex .= '(?=.*[A-Z])'; }           // Match at least 1 uppercase letter
    if ($req_symbol == 1) { $regex .= '(?=.*[^a-zA-Z\d])'; }    // Match at least 1 character that is none of the above
    $regex .= '.{' . $min_len . ',' . $max_len . '}$/';

    if(preg_match($regex, $password)) {
        return TRUE;//pw is valid
    } else {
        return FALSE; //pw is not valid
    }
}



//If we have made it this far, send the result back to the requester
echo json_encode($result); 
?>