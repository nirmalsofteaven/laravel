<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
use Session;
use Sentinel;
use DB;
use Illuminate\Support\Str;
use Cartalyst\Sentinel\Checkpoints\NotActivatedException;
use App\Models\User;
use Validator;


class AuthController extends Controller
{
  public function postlogin(Request $request)
  {
    $user = User::where('email',$request->email)->get();
    //$user = User::where('email',$request->email)->first();
    foreach($user as $key => $dbusers)
    {
      $usersexits = $dbusers->id;
    }
    
    $active = DB::table('activations')->where('user_id',$usersexits)->get();
    $count = count($active);
    
    if($count == 0)
    {
      DB::table('activations')->insert([
        'user_id' => $usersexits,
        'code' => str_random(24),
        'completed' => '1'
      ]);
    }
               Sentinel::authenticate($request->all());
               $credentials = $request->only('email', 'password');
               if(Auth::attempt($credentials))
               {
                    $user = Sentinel::findById($usersexits);
                    //Sentinel::activate($user);
                  // echo '<pre>';print_r($user['type']);exit;
                   $role = DB::table('role_users')->where('user_id', $usersexits)->first();
                   if($role) {
                       Session::put('logged_in_user_role', $role->role_id);
                       $roleDetails = DB::table('roles')->where('id', $role->role_id)->first();
                       Session::put('logged_in_user_role_details', $roleDetails);
                        //echo '<pre>';print_r($user);exit;
                       Session::put("type",$user['type']);
                       Session::put("userId",$user['id']);
                   } else {
                       Session::put('logged_in_user_role', 0);
                       Session::put('logged_in_user_role_details', []);
                   }
                  if($request->get("remember_me")==1){
                      setcookie('email', $request->get("email"), time() + (86400 * 30), "/");
                      setcookie('password',$request->get("password"), time() + (86400 * 30), "/");
                      setcookie('remember_me',1, time() + (86400 * 30), "/");
                  } 
                  $user = User::where('email',$request->email)->first(); 
                  Session::put("name",$user['name']);
                  return redirect('admin/dashboard');   
               } 
               else{
                   Session::flash('message', __("message.Login Credentials Are Wrong")); 
                   Session::flash('alert-class', 'alert-danger');
                   return redirect()->back();
               } 
  }
  public function register(Request $request)
  {
      $request->validate([
          'name' => 'required|string',
          'email' => 'required|string|email|unique:users',
          'password' => 'required|string|',
          'c_password'=>'required|same:password',
      ]);

      $user = new User([
          'name' => $request->name,
          'email' => $request->email,
          'password' => bcrypt($request->password)
      ]);

      if($user->save()){
          return response()->json([
              'message' => 'Successfully created user!'
          ], 201);
      }else{
          return response()->json(['error'=>'Provide proper details']);
      }
  }

  public function login(Request $request)
  {
	  $request->validate([
	    'email' => 'required|string|email',
	    'password' => 'required|string',
	    'remember_me' => 'boolean'
	  ]);
    Sentinel::authenticate($request->all());

	  $credentials = request(['email', 'password']);
	  if(Auth::attempt($credentials))
	  {
	    $user = Sentinel::findById($user['id']);
      Sentinel::activate($user);
	  }

	  $user = $request->user();
	  $tokenResult = $user->createToken('Personal Access Token');
	  $token = $tokenResult->plainTextToken;


	  return response()->json([
	    'access_token' => $token,
	    'token_type' => 'Bearer',
	  ]);
  }

   public function user(Request $request)
   {
	  $user = Auth::user();
	  return response()->json($user);
   }

    public function logout(Request $request)
    {
      $user=Sentinel::getUser();
       if($user->usertype=='2'){
          Sentinel::logout();
        
           return redirect("/admin");
       }else{
         Sentinel::logout();
         
            return redirect("/admin");
       }

     
    }
}
