<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Auth;

class UserController extends Controller
{

    public function store(Request $request)
{
    // Validar los datos de entrada
    $validatedData = $request->validate([
        'name' => 'required|max:255',
        'email' => 'required|email|unique:users',
        'password' => 'required|min:6',
        'rol' => 'required|min:6',
    ]);

    // Crear el usuario
    $user = User::create([
        'name' => $validatedData['name'],
        'email' => $validatedData['email'],
        'password' => bcrypt($validatedData['password']),
        'rol' => $validatedData['rol'],
    ]);

    // Opcionalmente, puedes generar un token de acceso para el usuario
    $token = $user->createToken('example')->accessToken;

    // Enviar respuesta
    return response()->json(['user' => $user, 'token' => $token], 201);
}

    /**
     * Display a listing of the resource.
     */
    public function loginUser(Request $request): Response
    {
        $input = $request->all();

        Auth::attempt($input);

        $user = Auth::user();

        if (Auth::attempt($input)) {
            $user = Auth::user();
            $token = $user->createToken('example')->accessToken;
            return Response(['status' => 200, 'token' => $token], 200);
        } else {
            return Response(['error' => 'Unauthorized'], 401);
        }
        
        //$token = $user->createToken('example')->accessToken;
        //return Response(['status' => 200,'token' => $token],200);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function getUserDetail(): Response
    {
        if(Auth::guard('api')->check()){
            $user = Auth::guard('api')->user();
            return Response(['data' => $user],200);
        }
        return Response(['data' => 'Unauthorized'],401);
    }

    /**
     * Display the specified resource.
     */
    public function userLogout(): Response
    {
        if(Auth::guard('api')->check()){
            $accessToken = Auth::guard('api')->user()->token();

                \DB::table('oauth_refresh_tokens')
                    ->where('access_token_id', $accessToken->id)
                    ->update(['revoked' => true]);
            $accessToken->revoke();

            return Response(['data' => 'Unauthorized','message' => 'User logout successfully.'],200);
        }
        return Response(['data' => 'Unauthorized'],401);
    }

}
